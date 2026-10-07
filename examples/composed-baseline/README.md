# composed-baseline

The strongest alternative a competent engineer assembles today out of formats
that already ship, put through the same two corpora as the Chio
cross-organization receiver, so that "nothing else defines this object" can be
checked rather than asserted.

This is a standalone Cargo project, deliberately not a member of the Chio
workspace: it is the alternative, not part of the system under comparison, and
it carries its own lockfile so the parts it composes are pinned independently.

## The alternative

One call is four published documents' worth of shape:

- a tool call as the Model Context Protocol defines it (`tools/call`, with
  `params.name`, `params.arguments` and the per-request fields MCP requires in
  `_meta`);
- an agent-to-agent message as A2A defines it (`SendMessageRequest`, whose
  `Message` carries `messageId`, `contextId`, `taskId`, `parts`,
  `referenceTaskIds` and a metadata map, with the tool call in a data part);
- a delegated credential as OAuth 2.0 token exchange defines it (the
  `access_token` of a successful exchange, a JWT whose claim set carries `iss`,
  `sub`, `aud`, `exp`, `nbf`, `iat`, `jti`, `scope`, `client_id` and the actor
  claim `act`);
- a workload identity as SPIFFE defines it (SPIFFE IDs for both parties, the
  peer authenticated by the key in its X509-SVID, the counterparty's SVID and
  issuer keys installed by a federated trust bundle).

`src/spec.rs` names the document, version and section behind every field on the
wire, and `tests/corpora.rs` walks the bytes an admissible call serializes and
fails on any path no document defines. That check is the point of building it
this way: an argument about what the alternative cannot carry has to be an
argument about published specifications, not about a schema in this repository.

Its one dependency on Chio is `chio-core-types`, for Ed25519 and RFC 8785
canonical JSON. That is deliberate: both sides then sign and hash with the same
code, so a latency difference between them is a difference in what they check
and never a difference in whose primitives were linked. The credential is a JWS
in compact serialization signed with EdDSA, so the container is the one the
documents describe. Its store is SQLite in WAL with `synchronous = FULL`, which
is what the Chio receipt store runs under, so a per-call byte or millisecond
figure taken here is comparable with one taken there.

## Two wirings

The same code runs under two profiles, and both are reported.

`composed` is what the parts produce when each is used the way its
specification documents: the call is well formed, the credential verifies
against the issuer the trust bundle names, its audience names this receiver,
its scope covers the action and resolves an agreement, and the policy engine is
handed the message's own metadata as its evaluation context.

`hardened` is the same parts with every check an operator could reasonably add
written in: the credential's own identifier is claimed in a second replay
table, its window is bounded by a constant the receiver holds, it must be in
its canonical encoding, the SVID key and the issuer key must be distinct, the
acting party must be the workload the channel authenticated, a retired
agreement is refused, the version the scope asserts must equal the version the
receiver holds, attributes whose names the receiver owns are refused in every
slot the formats leave open, referenced tasks must resolve in the receiver's
own table, and the rule gating the action resolves its approval locally.

Both are reported. Reporting the hardened wiring alone would credit the
composition with checks that no part of it requires; reporting the composed
wiring alone would understate what a careful operator reaches. The distance
between them is itself a result: the same parts yield either, and nothing in
the composition records which one an operator deployed.

## What is carried and what is not

`src/substitution.rs` answers, for each of the fifteen fields of the Chio treaty
binding reference, what carries it here and whether a substitution is noticed.
Where a format does carry something, the row says so: an agreement identifier
travels as a scope value, an action as the tool name beside a scope value, an
approval reference as an argument of the tool, both parties of the delegation as
`sub` and `act.sub`, and their order as the nesting of `act`. A task identifier
even gives the receiver something it minted itself. Eight of the fifteen have no
field anywhere in the set.

`src/carriers.rs` is the other half: for every fact with no carrier, or none the
receiver can resolve, the slot a value would have to travel in, whose signature
covers that slot, and the work an operator would have to do. Three witnesses
drive that work rather than describing it, over the fact the comparison turns
on. An agreed name the receiver does not read changes nothing. The same name,
once the receiver reads it, refuses a caller that reports its stale view
honestly. It still admits the caller that asserts the version the receiver
holds, because the value is written by the caller into a slot no signature in
the set covers.

## The admission path

Thirty numbered steps with a closed denial vocabulary, so a denial can be
reported at a step. `src/receiver.rs` carries the path and `DENIAL_CODES` the
vocabulary. A store failure is not in that vocabulary: it leaves the path as an
error, so the tool never runs and no record is written.

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
