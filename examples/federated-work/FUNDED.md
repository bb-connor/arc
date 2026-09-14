# Verified funding, native Finding and observed settlement

The experimental entry point connects a private-chain `ChioWorkClaimEscrow`
allocation to one durable native operation and one budget hold. The kernel
executes the existing W0 OpenAPI checker. Recovery retains the original request,
operation, hold and allocation, including when the worker is killed before its
acknowledgement reaches the native journal.

The admission-only command leaves the contract **Funded** and native payment
**pending**. The lifecycle command continues through a native Finding artifact,
custody retrieval, independent W0 verification, observed claim and decision,
and an actual mock ERC20 payout or refund on those same identities.

## Reproduce

Use Rust, Node and the locked contract dependencies. From the repository root:

```sh
cd contracts
pnpm install --frozen-lockfile --ignore-scripts
cd ..
CARGO_TARGET_DIR=target cargo build --locked --manifest-path examples/federated-work/Cargo.toml
python3 -B examples/federated-work/funded_smoke.py
```

For the lifecycle, set `CHIO_FUNDED_PYTHON` to a Python environment installed from
`python_buyer/requirements.txt` with `pip install --require-hashes -r ...`:

```sh
export CHIO_FUNDED_PYTHON=/absolute/path/to/venv/bin/python
python3 -B examples/federated-work/funded_lifecycle.py
CHIO_FUNDED_PYTHON="$CHIO_FUNDED_PYTHON" CARGO_TARGET_DIR=target cargo test --locked \
  --manifest-path examples/federated-work/Cargo.toml funded_work::tests -- --ignored --test-threads=1
```

`experimental-funded-lifecycle STATE MODE [FAULT]` supports `pay`, `reject`,
`absent` and `unavailable`. `preexpired` exercises an independent caller's
separate timeout transaction. With a fault, `pay-expired` and `reject-expired`
advance fixture time past the original deadlines after killing the worker.
The harness enumerates the supported fault points. Each invocation requires
new empty state; each recovery within that invocation reopens the same state.
The implementation digest intentionally rejects older experimental databases.
On Unix, `unknown` kills the worker after W0 executes but before native outcome
recording, then refunds without replay. `undispatched` kills after allocation
binding but before acknowledgement, then refunds and completes the original
pre-dispatch release. Both are exercised by the lifecycle harness.

The smoke runs the normal path and four actual SIGKILL scenarios. It checks
the original native IDs, authoritative SQLite operation/hold counts, actual
W0 invocation count, native payment state, budget hold disposition and independent
contract/token balances. Node owns a fresh
in-process Ganache chain. The native worker can request only the fixed lifecycle operations for
its one allocation over an owned local socket. There is no external RPC option,
external key input or legacy credit fallback. Process-loss scenarios require
Unix.

To retain a private reproduction directory and print its public summary:

```sh
state=$(mktemp -d /tmp/chio-native-funding-XXXXXX)
target/debug/chio-federated-work experimental-funded-smoke "$state"
```

Append `after-stage`, `before-bind`, `after-hold` or `after-tool` for a killed-worker run. State
must be empty. The directory contains generated private keys and capability
material; retain only the emitted summary as public evidence.

Run the standalone Rust checks explicitly; root workspace tests exclude this
example:

```sh
CARGO_TARGET_DIR=target cargo test --locked --manifest-path examples/federated-work/Cargo.toml
CARGO_TARGET_DIR=target cargo clippy --locked --manifest-path examples/federated-work/Cargo.toml --all-targets -- -D warnings
cargo test -p chio-kernel --test durable_admission_sqlite
```

## Admission contract

`chio.experimental.native-funded-w0-agreement.v1` is an example-local signed
agreement. Buyer and provider signatures cover the receiver policy digest,
native authority UUID, complete original request digest, original request ID,
chain/deployment/code pins, actors, amount and deadlines. Amounts use canonical
positive decimal strings bounded by `2^53 - 1`. The profile fixes the price at
100 mock base units; native `XTS` units map one-to-one to that pinned token.

The receiver owns the funding source. Work requests cannot supply an observation
or a `finalized` flag. Rust independently checks the allocation ABI, exact Funded
event, successful transaction, exact incoming token transfer, immutable work
terms, unclaimed state, token backing and block-pinned reads. The receiver also
checks code hashes, genesis, contiguous ancestry, two descendant blocks and a
separate head read. The chain head must be recent; the observation must complete
within 30 seconds. Original capability expiry cannot exceed `submitBy` and is
checked again by native admission before dispatch.

`chio.experimental.local-confirmed-funding.v1` describes a single owned private
chain on chain ID 31337. Its confirmation rule does not establish public-chain
finality, independent witnesses, fraud/dispute coverage, independent companies,
cross-border operation or attested host confinement. An observer or receiver
host compromise remains outside this profile. Existing legacy channel funding
and public settlement-proof formats retain their original meanings.

The journal commits the signed agreement and exact request before entering the
kernel. The kernel's opt-in `require_durable_request_retention` setting retains
the original request on direct admission, without creating a nonce-preflight
hold. The funding adapter reads that request through the fenced authority and
matches the native payment journal before committing allocation-to-operation and
hold correlation. A repeated authorization cannot reassign either identifier.
The allocation's agreement digest prevents re-signing a fresh request or fresh
authority against the same deposit.

## Finding and settlement checks

`chio.experimental.native-funded-submission.v1` binds the original allocation,
agreement, authority UUID, request digest, operation, hold, authorization and
retained native outcome. `Native::evidence` reads the qualified outcome store,
checks the operation/outcome link and raw return digest, and exports the actual
W0 output. It does not infer completion from the example's invocation counter.
Input and output bytes are retained under SHA256 content addresses. A canonical
`chio.finding.v1` artifact commits the standard media-type/base64 reveal envelope.
The provider signs the Finding and exact submission. Strict raw-first decoding
rejects duplicate keys, noncanonical encodings, unknown fields and typed drift.

The prepayment Finding uses **asserted** evidence and guarantee classes. A native
completed payment receipt does not yet exist, and this profile does not claim
receipt/checkpoint, bond, status-liveness, lineage or runtime-assurance facets.
The separate experimental W0 decision requires original native output binding,
retrievable custody and an independently implemented Python checker over the
exact original input. It is not a general `chio-finding-verifier` report or a
promotion to the Finding's `verified` evidence class. Unsupported or unavailable
authority/evidence issues no decision. An authenticated incorrect result receives
a signed rejection. The negative fixture signs a wrong provider submission; it
does not edit the native outcome or rerun the tool.

The receiver policy pins a separate Ed25519 verifier key. The decision binds the
observed original claim transaction/block, submission commitment, Finding ID,
checker implementation and native identities. Only a claim observed in its
resolution window can produce that decision. The owned chain signer verifies
the Ed25519 decision before producing the contract's EIP-712 authorization.
All these actors and keys belong to one local fixture, not separate companies.

Claim, decision, payout and refund actions retain exact signed transaction bytes before broadcast.
Rust checks the intent and ABI call; the existing ethers reconciler independently
decodes the transaction, signer, nonce, fees and calldata. Retrying uses the same
bytes and hash. Missing inclusion, occupied nonces or changed prior inclusion
remain uncertain. Rust then checks the actual receipt, two descendant blocks,
separate current-head read, immutable terms, commitment/decision and exact escrow
and ERC20 events. Previously observed inclusion cannot silently move to a new
block. Source files for the Python checker and Node transport are pinned.
The public summary independently enumerates mined blocks and receipts and
compares transaction hashes with the retained intents. A separate negative
control sends duplicate idempotent claim/decision transactions: enumeration
catches both even though their replay receipts emit no events.

The lifecycle advances private chain time to exercise deadlines without waiting
in real time. Admission retains its wall-clock freshness checks. Lifecycle reads
retain the 30-second receiver observation limit and validate the current private
chain snapshot. These are bounded private-chain observations, not public finality.

## Recovery and remaining work

| Process loss | Recovery |
| --- | --- |
| After funding journal commit, before native admission | The same signed request executes once |
| After native hold creation, before funding binding | Original operation and reversed hold remain inspectable; native payment is not authorized; no tool replay |
| After native hold binding, before rail acknowledgement | Recover the original authorization, preserve pending release and open budget hold; no tool replay |
| After W0 executes, before native outcome recording | Native execution remains `OutcomeUnknownAfterDispatch`; no replay |

Before the funding journal binds a native operation, observer failure is a definite
refusal. A journal commit error remains uncertain. Native recovery queries the
rail using the original operation before cancelling an unacknowledged payment.
Only an authoritative `NoAuthorization` permits cancellation; a committed held
authorization is recovered into the same native journal. Unavailable, panicking
or incompatible queries preserve uncertainty. An outstanding release resumes its
existing durable intent after an interruption. Other rails must provide the same
strong negative-query contract to support this recovery path.

The adapter refuses capture, release and refund until their contract successors
are independently observed. It never reports local bookkeeping as token payment.
Startup reconciliation errors are retained in the report and block new work;
reads of the original binding remain available. The journal admits at most 63
allocations and retains their identities indefinitely, leaving one native
retention slot for recovery administration. This is a bounded experiment, not
the later sustained-capacity trial.

Payout acknowledgement completes the original native capture and operation.
Refund acknowledgement is a **release** of the funded allocation. If native
execution already recorded a positive cost, its original capture intent remains
`Finalizing` / `Settling`; the report independently shows the verified refund.
This slice does not fabricate contractual zero-charge authority, reverse consumed
native work budget, erase execution uncertainty or refund an earned payout.
An unknown native outcome stays `OutcomeUnknownAfterDispatch`, with its original
open budget exposure, after financial refund. An undispatched authorization can
complete its already-authorized release and reverse the original budget hold.

Recovery first observes current escrow state. An unbroadcast submission or
unrecorded decision that missed its deadline can time out and refund while the
original signed artifacts and prepared transactions remain retained. A recorded
acceptance remains payable after deadlines. Public `expire()` followed by a
separate refund transaction is also supported. No database edits are needed.

Remaining Task 4 work includes a native authority for resolving an externally
rejected/timed-out positive capture, registered general work artifact/facet
integration, the funded parent-loss/earned-child trial and broader disclosure,
manifest, independent-operator and sustained-capacity qualification. The current
experimental schemas are example-local, not additions to the public registry.
