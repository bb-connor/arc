# Private rail recovery profile

The outbox extends the [funded W0 artifact experiment](README.md). It preserves
an exact signed transaction across loss of a rail worker. It does not integrate
native admission, classify native execution, authorize a new payment successor
or establish public-chain finality.

## Durable authority before broadcast

[rail_journal.py](rail_journal.py) stores a content-addressed intent, original
signed type-2 transaction, transaction hash and signer nonce before any RPC
broadcast. Each journal is pinned to one actor, chain ID, escrow deployment,
runtime code hash and genesis hash. Each allocation/action pair has one intent;
one occupied signer nonce cannot acquire another operation, including after
inclusion or uncertainty. Exact preparation retries return the original bytes.
The transaction's signature, signer, chain, nonce, destination, zero native value,
fee/gas envelope, empty access list, calldata, action and allocation are checked
before dispatch by [the rail verifier](../../contracts/scripts/work-claim-recovery.mjs).

The intent is `chio.experimental.rail-intent.v1`, with exactly `schema`,
`operationId`, `allocationId`, `agreementDigest`, `action`, `actor`, `domain`,
`callData`, `gasLimit`, `maxFeePerGas`, `maxPriorityFeePerGas`. `operationId` is
SHA-256 of the RFC 8785 body excluding that field. Its restricted grammar uses
ASCII strings/objects only; the Node encoding is checked by the existing Python
canonical encoder at journal preparation. Numeric fields use canonical decimal
strings within the existing safe-integer limit. The gas ceiling is one million.
`domain` has exactly `chainId`, `escrow`, `runtimeKeccak256`, `genesisHash`.
Actions are `submit`, `decision`, `pay`, `refund`; the ABI method and arguments
must agree with the declared action and allocation.

The prepared record contains exactly `intent`, `nonce`, `rawTransaction`,
`transactionHash`. The journal's owner must be the recovered transaction signer.
This is one exclusive local signer stream for the selected deployment; it is
not distributed nonce coordination across independent journal copies.

## Inclusion and uncertainty

A prepared operation starts `Unknown`: preparation does not prove whether a
broadcast occurred. Recovery has no signing key and never asks a signer for a
new nonce. It queries the original transaction. With no prior inclusion, no
pending original transaction and the exact nonce currently available, it may
broadcast the original raw bytes. An unresolved earlier nonce waits; an occupied
nonce without the original receipt stays uncertain. A missing receipt never
proves the original operation failed.

Before recording inclusion, the worker checks actual chain/deployment pins,
transaction fields and signature, receipt identity, block hash and transaction
position in the observed canonical block. It also checks the allocation's
agreement and resulting contract state. A successful payment requires `Paid`
with the exact amount and no refund. A reverted transaction is `Reverted`, never
paid. The journal retains the first inclusion observation immutably. Every
restart revalidates it against the live private chain.

The exact observation fields are `transactionHash`, `blockHash`, `blockNumber`,
`transactionIndex`, `status`. Status is `Included` or `Reverted`, not `Final`.
An unavailable or changed observation sets the journal's current state to
`Unknown` while retaining the original evidence, raw transaction and occupied
nonce. A later identical, valid inclusion may clear uncertainty. Re-inclusion in
a different block, a mined revert or a necessary fee replacement needs a future
explicit successor protocol; this slice does not synthesize one. This deliberate
limit preserves the original authorization but can sacrifice liveness.

Chain reads come from one trusted private Ganache instance. Matching a block
hash from that RPC is not a receipt Merkle proof, independent observer quorum or
public finality guarantee. Native integration must use the stronger existing
settlement proof and finality requirements, not promote this local observation.

## Custody, limits and crash boundaries

Both stores use owner-local mode-0600 regular files in mode-0700 directories,
FULL-synchronous SQLite transactions and readback. [owned_sqlite.py](owned_sqlite.py)
shares their file boundary. The outbox has 64 permanent operation slots, each
bounded to 16 KiB of preparation plus 4096 bytes for an observation. Observation
capacity is reserved by these slot bounds; this is a logical quota, not a disk
block reservation. New operations cannot evict or reuse old slots. Hash/index
consistency is checked before assigning a new nonce. The host and filesystem
remain trusted: same-database hashes do not resist a malicious administrator,
coordinated rollback or cloned journals.

The harness owns Ganache, the synthetic signing account and the workflow. A
separate worker receives public scope/configuration and reads the retained signed
transaction. Its environment contains only `PATH`; no signing key is passed.
Its IPC broker permits a narrow read-only RPC set and only that exact raw
transaction for broadcast. There is no network RPC listener. These construction
checks do not claim native confinement or independent key administration.

Tests SIGKILL the actual worker at four acknowledged boundaries:

1. After durable preparation, before broadcast.
2. After the real chain accepts the broadcast, before the worker receives its response.
3. After receipt/state verification, before recording the observation.
4. After durable observation, before returning completion.

A fresh process reopens the same journal, and another restart checks idempotence.
The tests verify SIGKILL, exact operation/hash/nonce, one included transaction,
one payment and exact token balances. A child case performs this recovery after
the parent refunds. The parent tool process is not killed; only the rail worker
is. No native admission operation or original native financial hold exists in
this experiment.

## Reproduce

Use the dependencies and standalone Rust binary described in [README.md](README.md).

```sh
python -B -m unittest discover -s examples/funded-work -v
CHIO_W0_PYTHON=/absolute/path/to/python node --test \
  contracts/scripts/work-claim-recovery-core.test.mjs \
  contracts/scripts/work-claim-recovery.test.mjs \
  contracts/scripts/work-claim-w0.test.mjs
```

To retain a standalone child run and its journal, use a new state directory:

```sh
state_dir=$(mktemp -d /tmp/chio-rail-recovery.XXXXXX)
CHIO_W0_PYTHON=/absolute/path/to/python node contracts/scripts/work-claim-recovery-demo.mjs \
  child after_broadcast "$state_dir" --output "$state_dir/public-result.json"
```

The scenario may be `accepted` or `child`; kill points are `before_broadcast`,
`after_broadcast`, `after_observation`, `after_recorded`. The report retains public
artifacts, killed worker identity/signal, journal snapshots, exact signed
transaction, receipts/events and balances. The private fixture state remains
local. Ganache is ephemeral; the retained journal is not proof that its old
private-chain inclusion remains available after the run ends.
