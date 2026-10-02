# Public authority enrollment and a separate funded-work verifier

The provider can now provision native funded-work authority from public role pins
and an externally signed Finding context. Its directory begins with only its own
seed. A separate verifier process observes the original claim, checks the actual
Finding and output, commits a signed decision in its own custody, and hands that
decision back for the original payout or refund.

This slice builds on `919bd0546f5fccc70cf70f0543027fafe18f96de` in the isolated
`feat/funded-native-admission` worktree. The [qualification manifest](30-authority-verifier-evidence.json)
binds the source, executable, commands and public artifacts. Earlier reports and
evidence remain historical and unchanged.

## Provision public authority before agreement

Generate each role's seed with `chio-federated-work init ROLE_STATE`. Select six
distinct Ed25519 public keys administratively: `buyer`, `provider`, `verifier`,
`checkpoint`, `status` and `governance`. The pins file contains those exact fields.
The governance and status signers build the existing bounded execution context;
the provider verifies that context against its separate public pins.

```sh
target/debug/chio-federated-work experimental-authority-context GOVERNANCE STATUS PINS.json EXPIRES_AT CONTEXT.json
target/debug/chio-federated-work experimental-provider-enroll PROVIDER PINS.json CONTEXT.json DOMAIN.json
```

The provider requires an otherwise empty directory containing its original
`key.seed`. It durably retains the exact public enrollment before provisioning
native authority and funding custody. Completed retries compare the same context,
domain, policy, implementation and native authority UUID. Incomplete bootstrap,
changed keys, missing stores and substituted authority are preserved and denied.
There is no automatic repair by replacing an original authority. Context creation
needs only the governance/status seeds; provider enrollment never reads them.

The existing context's unrequested delivery, replay and collateral authorities
remain fixture placeholders. They add no verified assurance. This is public key
provisioning for the bounded execution profile, not an organizational identity or
cross-border legal identity system.

## Export, decide and import

The verifier's administrative enrollment has exact fields `schema`, `policy` and
`agreement`, using `chio.experimental.funded-verifier-enrollment.v1`. Initialization
checks its own seed against the verifier key in that original public enrollment.
The complete bilateral agreement and policy are immutable for this custody slot.

```sh
target/debug/chio-federated-work experimental-verifier-init VERIFIER ENROLLMENT.json
target/debug/chio-federated-work experimental-verifier-export PROVIDER REQUEST_ID OBSERVER.sock REQUEST.json
target/debug/chio-federated-work experimental-verifier-decide VERIFIER REQUEST.json OBSERVER.sock DECISION.json
target/debug/chio-federated-work experimental-verifier-import PROVIDER REQUEST_ID OBSERVER.sock DECISION.json
```

The request schema is `chio.experimental.funded-verifier-request.v1`. It carries
the original signed submission and execution bundle, input, original output,
submitted output and prepared claim transaction. It carries no private native
request, capability token or provider-selected observation. Input and output are
disclosed to the selected verifier; this reproduction uses public fixture data.
Files must be exact canonical typed JSON within 256 KiB. Outputs are created
exclusively with private permissions; existing files remain unchanged.

The verifier authenticates the original authority UUID, operation, hold,
authorization, request commitment, outcome, raw outcome commitment, allocation,
policy, action input, original output and checkpoint standing. The public path
checks signed commitments and action bytes. It does not reconstruct the complete
private request or raw outcome preimages, nor independently authorize financial
capture waivers. Native execution and import retain their additional original
request, authority-store and execution-custody checks.

The verifier queries its configured observer for the original prepared claim. It
checks deployment/domain, immutable terms, transaction inclusion, two confirmed
descendants, commitment and the resolution window. The actual Finding verifier
and pinned Python W0 checker determine the existing signed decision v2. A valid
incorrect output produces rejection. Invalid signatures, unavailable authority,
unavailable observation and checker failure produce no financial decision.

A checker can outlive the original claim or authority. After checking finishes,
the verifier observes the original claim again and revalidates the execution,
Finding authority and resolution window before signing. It rejects a changed
claim transaction/block or an expired claim. Only the final observation and fresh
assessment enter custody. This remains a receiver-owned point-in-time observation,
not an atomic lock on subsequent chain activity or public-network finality.

## Original custody and recovery

Provider export commits its original handoff request before publication. Local
and external decision selection exclude one another within the funding journal's
writer transaction. Once delegated, ordinary execution cannot fall back to local
verifier signing. New export validates current authority; keep the exported
request for historical recovery after its authority expires.

The verifier uses an explicitly initialized SQLite database, FULL synchronous
writes, serialized writers, one immutable enrollment and one first-response slot.
Request, actual observation and decision commit together before file publication.
Exact retries verify retained public authority at the original assessment time
and return the original decision bytes without a signer, observer or checker.
Conflicting requests and missing, partial or corrupt custody fail closed. This
historical replay does not refresh standing or mint another decision.

A first provider import also obtains its own fresh original-claim observation and
requires the resolution window. It validates the decision against the original
native submission and execution bundle before retention. An already retained
exact decision can replay offline; a conflicting decision cannot replace it.
The existing lifecycle then records, pays or refunds the original allocation.

## Process reproduction and qualification

```sh
CARGO_TARGET_DIR=target cargo build --manifest-path examples/federated-work/Cargo.toml --locked
CHIO_FUNDED_PYTHON=/path/to/pinned/python python3 -B examples/federated-work/test_authority_verifier.py
```

The owned private-chain harness creates role seeds in separate originating
directories through actual CLI processes. It performs public provider enrollment,
external checkpoint handoff, separate verifier observation/checking/decision, and
provider import followed by payout or rejected-output refund. No role seed is
copied into the provider directory. The verifier's observer socket rejects
transaction preparation and broadcasting.

Both scenarios deliberately fail with an unavailable observer and checker, then
force an output-file collision after decision custody commits. They remove the
verifier seed and stop its observer before publishing and replaying the original
decision. Python verifies each Rust-produced public execution witness with
separately supplied allocation pins. Balances, exact original identities, one
execution and unique funding/claim/decision/settlement events are asserted.
Additional CLI checks reject twelve malformed or conflicting requests and twelve
corrupted/missing custody copies across the two scenarios. Original custody still
replays exactly afterward.

All 82 selected standalone Rust tests pass: 76 regular tests and all six explicitly
selected private-chain tests, including ten new authority/verifier regressions.
Python passes 28 public execution-verifier tests and six canonical wire tests.
All 20 selected owned process scenarios pass: two separate-verifier lifecycles,
two checkpoint handoffs, seven native refund-resolution scenarios, four
earned-child scenarios and five execution-custody recovery scenarios. Those
regressions include 15 actual SIGKILL events.

Standalone Clippy with warnings denied, standalone/workspace formatting, Rust
file hygiene and diff checks pass. The manifest records the exact executable
used for the process suites and all 75 selected source-file hashes. Original
checkout verification confirms all 3,688 saved file hashes and modes, original
HEAD/branch and dirty state remain unchanged. Ganache used the JavaScript fallback
for unavailable optional ARM native bindings. Workspace crates and dependencies
were unchanged; no full-workspace test run, fuzz campaign or new formal-source
review was performed for this example-only slice. Review was performed inline
without sub-agents; see the [review record](authority-verifier-evidence/review.md).

## Remaining delivery gate

These are separate processes on one host under one administrator. Directory
selection does not enforce OS access isolation. The fixture coordinator still
reads buyer and provider seeds to assemble bilateral consent; context construction
reads governance and status seeds together. This does not establish independently
administered companies, independent RPC operators or hostile-network transport.
The next concrete slice is public bilateral signature exchange and enforced role
filesystem/process isolation, then qualification on separately administered hosts.

Capacity remains one allocation per enrolled checkpoint log and verifier custody
slot. Provider funding and operator journals have no external rollback anchor.
Standing has no external revocation feed. The native receipt-store same-signer
rule and workspace dependencies remain unchanged. Python verifies public
execution authority, not chain funding or financial backing. Useful-work and
verification-cost measurements, broader Finding assurance and sustained capacity
remain later gates. Public deployment, remote CI, release qualification and real
funds remain open.
