# Checkpoint custody outside the provider process

An original funded native operation can now export its execution receipt to a
separate checkpoint operator and import the authenticated response. The provider
does not need checkpoint or status private keys. The resulting Finding follows
the existing observed claim, signed decision and original payout/refund paths.
The existing Python verifier consumes the public Rust-produced witness.

This slice builds on `bc8ca82e0016f8e76a0d449d33e032d79e9f8b9b` in the isolated
`feat/funded-native-admission` worktree. The [qualification manifest](28-checkpoint-handoff-evidence.json)
records current source, executable, commands and public artifact hashes. Earlier
execution reports and their evidence remain historical and unchanged.

## Portable commands

All commands use `target/debug/chio-federated-work`. `PROVIDER` is the existing
native funded-work directory; `REQUEST_ID` identifies its original retained
request. The operator's directory contains only its separately held checkpoint
and status keys and its own custody database.

```sh
target/debug/chio-federated-work experimental-checkpoint-init OPERATOR ENROLLMENT.json
target/debug/chio-federated-work experimental-checkpoint-export PROVIDER REQUEST_ID REQUEST.json
target/debug/chio-federated-work experimental-checkpoint-sign OPERATOR REQUEST.json RESPONSE.json
target/debug/chio-federated-work experimental-checkpoint-import PROVIDER REQUEST_ID RESPONSE.json
```

Enrollment is an administrative input with exact fields `schema`, `authorityUuid`
and `context`. Its schema is `chio.experimental.execution-checkpoint-enrollment.v1`.
The complete context must match the original agreement and the operator's public
keys. Signing requests cannot change that enrollment. The request schema is
`chio.experimental.execution-checkpoint-request.v1`, with `contextSha256` and the
original `receipt`. The response uses the existing execution bundle v1.

Input files must be exact canonical typed JSON within 256 KiB. Output files are
created exclusively with private permissions; an existing file is preserved.
If publication fails, request a new output path. Operator custody commits before
publication, so this returns the original response without signing again. Receipt
actions disclose the W0 input; the example artifacts contain public fixture data.

Export/import take original native authority ownership without startup execution
or financial reconciliation. Their offline funding source cannot authorize a
financial successor. Export retains its handoff request before publishing it.
The ordinary evidence path then waits for the response and cannot fall back to
local signing. Local checkpoint retention and external handoff selection exclude
each other within the funding journal's writer transaction.

## Authority and recovery contract

Import checks the exact original native projection, operation, request, outcome,
hold, authorization and agreement. It verifies the pre-agreed checkpoint key,
one-leaf membership, chronology and signed standing for production/checkpoint
roles. Invalid signatures, revoked standing and conflicting checkpoints cannot
become provider custody. Import retains the checkpoint before the complete
bundle; an interrupted first import can finish with the same response. Custody
loss after Finding issuance still fails closed.

The operator uses an explicitly initialized SQLite database with FULL synchronous
writes, a single enrollment row, immutable committed custody and serialized
writers. The first request and response commit together before response bytes
leave the process. A changed request cannot consume another sequence-1 checkpoint.
Exact retries validate the retained response and return its historical bytes even
after private keys are removed. A changed key cannot sign pending original work,
and signing never recreates absent state. This is historical evidence replay;
fresh claim admission continues to validate at the current time.

The native receipt-store checkpoint same-signer rule is unchanged. This handoff
uses the already separate, pre-agreed one-leaf log. The operator and provider
funding journals are trusted local custody boundaries without the native
authority database's external rollback protection. Restoring an old operator
database or copying the same keys to another initialized directory is outside
this slice's protection. The operator issues bounded local standing, with no
external revocation-feed integration.

## Reproduce the process boundary

```sh
CARGO_TARGET_DIR=target cargo build --manifest-path examples/federated-work/Cargo.toml --locked
CHIO_FUNDED_PYTHON=/path/to/pinned/python python3 -B examples/federated-work/test_checkpoint_handoff.py
```

For each payout and rejected-output refund, the harness starts three operator
processes (initialize, sign, exact replay) and two provider handoff processes
(export, import), all with distinct state directories. It removes both operator
signing seeds before the replay. Python checks the final public witness against
external pins from the original funding observation. Ten additional malformed,
noncanonical, oversized or changed-context CLI requests must fail without an
output file. Balances, original identities, one execution and unique observed
claim/decision/settlement events are asserted against the owned private chain.

The Rust regressions exercise concurrent operator connections, atomic custody
selection, signed authority substitutions, state loss/corruption, key rotation,
publication failure and missing post-Finding custody. Existing native evidence,
Finding, payment, resolution and earned-child checks remain separate regressions.

## Qualification

All 72 selected standalone Rust tests pass: 67 regular tests, including ten new
custody tests, and all five explicitly selected private-chain tests. Python passes
28 public execution-verifier tests and six canonical wire tests. The separate
operator harness passes payout and refund with both public witnesses independently
verified, plus ten rejected CLI artifact mutations.

All 18 selected owned process scenarios pass: two operator handoffs, seven native
refund-resolution scenarios, four earned-child scenarios and five execution
custody recovery scenarios. Those regressions include 15 actual SIGKILL events.
Standalone Clippy with warnings denied, standalone/workspace formatting and Rust
file hygiene pass. The final build preserves the exact executable used for the
process scenarios. Original checkout verification confirms all 3,688 saved file
hashes and modes, original HEAD/branch and dirty state remain unchanged.

Review was performed inline, with no sub-agents. The [review record](checkpoint-handoff-evidence/review.md)
records the atomic custody-selection correction and remaining trust boundaries.
Ganache used its JavaScript fallback for unavailable optional ARM native bindings.
The workspace crates and dependencies were unchanged. No full-workspace test run,
fuzz build or new formal-source review was performed for this example-only slice.

## Remaining operator delivery gate

This delivers a portable process and custody interface on one local host. The
fixture bootstrap still creates checkpoint/status keys and transfers them before
execution; it does not establish independent key provenance or independent
administration. Buyer and verifier operation remain part of the local harness.
The operator is Rust and the public witness verifier is Python; no second
checkpoint-signing implementation is claimed.

Next, replace fixture bootstrap with independently provisioned public authority
enrollment before agreement, then apply the artifact boundary to the funded-work
verifier's claim observation and signed decision. Qualify those roles under
separate administration, measure useful work and verification cost, and only then
expand beyond one allocation per log with rollback-aware checkpoint custody.
Public deployment, remote CI, release qualification and real funds remain open.
