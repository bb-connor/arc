# Verified funding and native admission

The experimental entry point connects a private-chain `ChioWorkClaimEscrow`
allocation to one durable native operation and one budget hold. The kernel
executes the existing W0 OpenAPI checker. Recovery retains the original request,
operation, hold and allocation, including when the worker is killed before its
acknowledgement reaches the native journal.

Successful authorization leaves the contract **Funded** and native payment **pending**. It does
not submit a claim, establish Finding facets, authorize a verifier decision or
withdraw ERC20 tokens. Those remain the next settlement steps of Task 4.

## Reproduce

Use Rust, Node and the locked contract dependencies. From the repository root:

```sh
cd contracts
pnpm install --frozen-lockfile --ignore-scripts
cd ..
CARGO_TARGET_DIR=target cargo build --locked --manifest-path examples/federated-work/Cargo.toml
python3 -B examples/federated-work/funded_smoke.py
```

The smoke runs the normal path and four actual SIGKILL scenarios. It checks
the original native IDs, authoritative SQLite operation/hold counts, actual
W0 invocation count, native payment state, budget hold disposition and independent
contract/token balances. Node owns a fresh
in-process Ganache chain. The native worker can only request an observation of
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

Next: map the registered work/submission/decision artifacts and Finding facets,
establish custodian retrieval, then correlate verifier-authorized claims,
withdrawals and refunds with this original native authority. Complete the
native parent-loss/earned-child and disclosure/manifest qualification before
claiming the complete funded-work vertical slice.
