# Buying a checked repair: the fair-exchange boundary

2026-09-13. Continuation of the breakthrough investigation after
[artifact reuse](25-artifact-validity-is-not-scarce-work.md).

The new experiment exchanges the real two-file Git-hook repair for durable
local test credits. An explicitly trusted checker opens the encrypted artifact,
binds the checked bytes and complete offer to an outcome authorization, and a
trusted settlement worker credits the seller and releases the key in one
SQLite transaction. Both existing outcome gates support the same result.

This builds a useful acceptance-and-delivery boundary, but it does not establish
trustless exchange or a breakthrough. It exposes the next missing mechanism:
verifying the correctness of concealed work before funding, without giving its
buyer or an operator the plaintext. Moving settlement to an external payment
rail would also require a new atomicity argument.

## Why acceptance alone is insufficient

The previous auditor let a consumer verify a repair without trusting its
producer's signature. If the producer wants payment for that repair, consumer
verification creates another problem: once the buyer has the source to run the
checker, the buyer can keep it and decline to pay.

The new harness makes that behavior executable. It copies the valid repair to
the buyer's artifact file, runs all seven native Git checks successfully, and
performs no settlement. The buyer has usable bytes and the seller receives
nothing. This is an intentionally discretionary-payment construction, not a
vulnerability in an existing escrow or production Chio protocol.

The opposite shortcut also fails. The seller encrypts the original buggy source
with AES-256-GCM and supplies the ciphertext, an artifact digest and a SHA-256
commitment to the key. A bare local hash-lock settlement accepts the correct
key, credits the seller 10 test units and releases the key. The buyer decrypts
exactly the buggy artifact. Correct encryption and key release have not checked
the repair's behavior. The same artifact fails all seven native Git cases,
leaving 21 hook markers.

The comparison therefore includes both sides of the exchange problem. Neither
plain delivery followed by discretionary payment nor an authenticated
ciphertext plus a key commitment establishes the desired guarantee.

## The implemented stronger control

The [Rust controller](../../../examples/outcome-ledger-comparison/src/graph/repair_exchange.rs)
uses the existing native behavioral checker and both existing outcome gates.
The [Python worker](../../../examples/outcome-ledger-comparison/src/graph/repair_exchange.py)
uses the installed `cryptography` AES-GCM implementation and SQLite. It is a
trusted local worker, not a network API accepting unauthenticated payment
commands.

Each offer binds a trade identifier, buyer and seller account names, a price,
an expiry and the checker contract digest. These terms are authenticated as
AES-GCM associated data. The offer also includes the ciphertext, nonce, key
commitment and plaintext artifact digest. Every encryption uses a fresh random
256-bit key and 96-bit nonce. No custom encryption primitive was implemented.
[AES-GCM API documentation](https://cryptography.io/en/latest/hazmat/primitives/aead/#cryptography.hazmat.primitives.ciphers.aead.AESGCM).

The trusted checker decrypts the offer and compares the resulting bytes with
the exact artifact already accepted by the native checker. This is a cache of
a completed behavioral check, not acceptance based on a seller-provided hash.
The wrong artifact is rejected by the same checking function used on the
successful path. A different valid repair would need its own native check;
this experiment's cache contains only this repair.

The selected verifier then signs an outcome whose artifact digest covers the
complete offer, under the owner-selected contract and logical slot. Gate
admission is exercised before settlement. This is direct outcome-gate use; it
adds no new kernel-dispatch or capability-enforcement claim.

Each independent trade starts with 100 test credits assigned to the buyer.
Funding reserves 10, leaving 90 available to the buyer and zero for the seller.
The durable settlement transaction checks the immutable funded offer and key,
then writes both the seller's 10-unit credit and the released key. The buyer
delivery command reads the public offer and committed settlement view, decrypts
the artifact and compares its exact bytes with the checked repair.

A refund is permitted only from the funded state at or after expiry. It restores
the reserved credits without releasing a key. Successful settlement and refund
are mutually exclusive terminal states. Every readback checks that available
balances plus locked credits total 100 and that a released key exists exactly
when the trade is settled.

The credit and key transition is atomic because both are in the same SQLite
transaction, with WAL and synchronous FULL enabled. The outer outcome gate is
in a separate database and does not magically make these writes atomic. The
trusted controller retains its gate permit while retrying or observing the
idempotent settlement operation, and completes that permit afterward.

## Executed adversarial and recovery cases

Each case runs against Chio and the independent receiver ledger. Both use the
same checker, ciphertext format and settlement sink, so differences in the
admission gate are not confused with differences in the payment implementation.

| Case | Observed terminal result per backend |
| --- | --- |
| Honest exchange | Buyer receives the checked repair; seller receives 10 credits |
| Buyer abandons after funding | Seller settlement completes without a further buyer acknowledgement |
| No settlement before expiry | Buyer receives a full refund; key remains unreleased |
| Kill after seller-credit SQL, before commit | Transaction rolls back; funded state and unreleased key survive; retry settles once |
| Kill after commit, before reply | Settled state and key survive; retry does not add another credit |
| Eight simultaneous settlement retries | One settlement event and one 10-credit transfer |
| Wrong decryption key | Attempt fails without changing funded state; correct-key follow-up settles |
| Changed price, recipient, trade or checker contract | All four altered offers fail without changing funded state; original offer settles |

The timeout fixture is named `seller_withholds` in the machine-readable result.
It withholds settlement until expiry; it does not model a seller withholding a
key from the checker. The trusted operator already has that key for checking.

The retained run has four actual SIGKILL terminations of settlement child
processes and sixteen concurrent settlement workers across the two retry
cases. The controller remains alive during these crashes. Completed gate
requests cannot claim another permit, successful settlement retries preserve
the existing event, early refunds fail, late settlement after refund fails,
and refund after settlement fails.

Across the sixteen protected trades, fourteen settle and two refund. Each has
one terminal settlement-store event and conserves all 100 test credits. The
bare hash-lock control is a separate seventeenth trade which pays for buggy
source. The native checker runs twice, for fourteen actual Git commit cases;
later comparisons reuse those results only for byte-identical artifacts.

## What the prior art already contributes

Campanelli, Gennaro, Goldfeder and Nizzardo describe zero-knowledge contingent
payments and attacks on earlier parameter-generation choices. The buyer needs
evidence that the committed key decrypts a correct good before funding. Their
work also distinguishes buying a good from buying a service whose valuable
information may already be conveyed by a proof. This is directly relevant to
selling repairs, findings and audits; those products cannot automatically use
the same payment predicate. The primary paper was read, but its cryptographic
protocols and attacks were not reproduced here.
[Zero-Knowledge Contingent Payments Revisited](https://eprint.iacr.org/2017/566.pdf).

FairSwap uses a smart contract as an adjudicator and avoids zero-knowledge
proofs for its construction. Its existence is a reason not to equate fair
exchange with one mandatory proof-system design. We reviewed its primary
abstract and metadata; the PDF fetch was denied, so this experiment makes no
claim to reproduce its circuit, dispute protocol or cost analysis.
[FairSwap](https://eprint.iacr.org/2018/740).

The authors' prototype for *WI is Almost Enough* separately connects a hidden
secret's encryption to a commitment and checks the secret's validity. Its
README describes a small secret circuit and an additional algebraic validity
proof. We inspected that implementation's documentation, not its correctness
or compatibility with the native Python/Git checker. No code from it was
incorporated.
[Contingent-payment prototype](https://github.com/security-kouza/cont-pay).

These are established mechanisms, not discoveries made by attaching an agent
to the exchange. The present implementation is deliberately a stronger
ordinary alternative to compare against when replacing operator trust.

## Judgment, limits and the next discriminating result

No breakthrough is established. The strongest objection is that the positive
result is ordinary custodial exchange with transactional storage, and both
gates reproduce it. That objection is correct. The implementation contributes
an executable comparison and a real repair workload, not a new fairness
mechanism.

All roles run under one administrative account. The operator sees the plaintext
and key before settlement and can violate the intended release policy. The
buyer delivery function reads only its offer and settlement view, but this run
does not enforce a new isolation boundary against a buyer with host filesystem
access. The source repair is already public in this repository, so the run
cannot demonstrate secrecy of an unknown valuable repair.

The credits have no monetary value. There is no external payment, deployed
market, bank, blockchain, independently administered buyer or seller, or live
agent solving a new repair. The deadline uses the harness's supplied logical
time. Controller death, operating-system or power loss, disk rollback,
operator equivocation, denial of service and external-rail finality are not
qualified by these child-process tests. The seven behavioral cases remain a
finite contract, not general program correctness.

What would change the judgment is an implemented useful exchange that removes
an actual trust or coordination requirement and survives the equally
provisioned alternative. For the concealed-repair direction, the next concrete
obligation is a proof or dispute mechanism linking the encrypted bytes to the
selected behavioral contract before funding. A signed checker assertion merely
retains checker trust. Replacing this SQLite sink with a remote payment call
does not preserve its atomicity.

## Reproduction and evidence

```sh
CARGO_TARGET_DIR=target cargo run --locked --offline \
  --manifest-path examples/outcome-ledger-comparison/Cargo.toml -- \
  --repair-exchange examples/outcome-ledger-comparison/fixtures/git-hook-repair/base .
CARGO_TARGET_DIR=target cargo test --locked --offline \
  --manifest-path examples/outcome-ledger-comparison/Cargo.toml
```

An optional final argument selects a new output directory. Existing Linux,
bubblewrap, Git and Python prerequisites remain. This mode additionally uses
`cryptography` from `/usr/bin/python3.12` (41.0.7 in the retained run) and SQLite
3.45.1. It changes no production runtime, repair source, dependency manifest,
lockfile or existing outcome-gate implementation.

Final validation passed all nine integration tests in 85.39 seconds, Clippy for
all targets with warnings denied, Rust formatting, Ruff lint and formatting,
and `git diff --check`. The paper passes log, bibliography, macro, page and word
checks at 12 pages and 4,976 body words.

The [result](evidence/26-checked-repair-exchange/repair-exchange-comparison.json)
and [manifest](evidence/26-checked-repair-exchange/manifest.json) retain process
observations, offers, outcome requests, public key-release views, JSON store
snapshots, validation logs and source hashes. Unreleased encryption keys,
private artifact working copies and binary databases are excluded from export.

This is local uncommitted work on `paper/roadmap-phase-0-1`, based on
`2b3b5af8cbfbc6f16ce6005de3f97cd149803b81`. It has no exact-commit remote CI,
release qualification, public activation or achieved-breakthrough claim.
