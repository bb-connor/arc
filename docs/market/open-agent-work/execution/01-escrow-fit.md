# Existing escrow fit for funded verifiable work

Date: 2026-09-14. Decision: preserve `ChioEscrow` semantics and prototype a
separate experimental work-claim escrow before native funded admission.
The existing contract supports real allocation and beneficiary payout, but
does not preserve a timely off-chain claim through its deadline. An adapter
cannot supply that missing authoritative state.

This is an F1 fit assessment, not a vulnerability claim against the contract's
documented expiry terms. Source baseline: `905583e951b66db2a3223afffad9dc5de5b0ef5f`.
The [six new characterization tests](../../../../contracts/scripts/funded-work-fit.test.mjs)
compile the actual Solidity sources and execute them on an in-process Ganache
chain. All six pass; the stronger timely-claim assertion deliberately fails.
Commands, logs and hashes are in [results](04-results.json).

## Enforced boundaries

Primary sources: [escrow](../../../../contracts/src/ChioEscrow.sol),
[interface](../../../../contracts/src/interfaces/IChioEscrow.sol),
[identity registry](../../../../contracts/src/ChioIdentityRegistry.sol),
[root registry](../../../../contracts/src/ChioRootRegistry.sol),
[dispatch preparation](../../../../crates/economy/chio-settle/src/evm/prepare.rs),
[dispatch finalization](../../../../crates/economy/chio-settle/src/evm/finalize.rs),
[public settlement verification](../../../../crates/economy/chio-web3/src/settlement_proof.rs).

| F1 requirement | Existing entry point | Caller/authority | Enforced binding | Time ordering | Counterexample or supporting test | Fit decision |
| --- | --- | --- | --- | --- | --- | --- |
| Exclusive funded allocation | `createEscrow` | Depositor; active operator and allowlisted token | Derived ID includes chain, deployment and all terms; exact incoming token balance delta | Future deadline; duplicate ID denied | One real deposit cannot fund a second escrow | Reuse the allocation mechanism; admission still needs independent finality observation |
| Exact work agreement | `deriveEscrowId`; `prepare_web3_escrow_dispatch` | Terms supplied by depositor; local instruction prepares call | Capability ID, parties, asset, ceiling, deadline, operator pin | Terms fixed at creation | Source: preparation hashes capability ID, not the full work agreement | New explicit agreement binding required; do not silently overload capability ID |
| Eligible beneficiary | `createEscrow`, `releaseWithSignature` | Release caller must be beneficiary | Fixed beneficiary, escrow ID and amount in authorization | Only live escrow | Outsider release denied; seller receives 100 | Fits beneficiary restriction; needs mapping from provider identity to payout address |
| Exact acceptance and custody | `releaseWithSignature`; detailed Merkle methods | Registered settlement key or registered root/proof | Receipt hash, amount, epoch, chain and contract; detailed leaves include escrow and payout metadata | Current operator eligibility and live deadline | Valid certificate accepted before deadline | Signature authenticates authority; no task checker, evidence custody or submission state is enforced |
| One-time service payment | Full signature release; detailed partial release | Beneficiary and operator authorization | Amount ceiling, consumed receipts per escrow and globally | State consumption before completed transfer | Duplicate full release denied after seller receives 100 | Useful existing protection; fixed-price F1 should avoid partial service payment initially |
| Refund | `refund` | Anyone may call; recipient fixed to depositor | Remaining amount; `refunded` terminal | Strictly after deadline; does not require unpaused state | Outsider triggers refund after expiry | Fits original timeout terms; cannot distinguish timely work awaiting verification |
| Timely claim survives certification delay | `_ensureLive`, release, refund | Block timestamp controls eligibility | No pending-claim or off-chain-submission binding | Release at or before deadline; refund after deadline | Same certificate succeeds in pre-expiry simulation and fails after expiry | Missing for proposed F1 promise |
| Key rotation | Identity registry plus escrow operator checks | Registry authority | Escrow's pinned Ed25519 key hash and current epoch/settlement key | Rotation does not migrate existing terms | Replacement operator key causes `OperatorKeyHashMismatch` | Must retain or explicitly migrate old claim authority; neither is automatic |
| Emergency pause | `setPaused` | Escrow admin | Global creation/release gate | Refund remains available after expiry while paused | Paused release fails; buyer is refunded | Admin availability/trust affects seller eligibility; new profile must define earned-claim access |
| Finality and reorg | `finalize_escrow_dispatch`; `verify_public_settlement_proof` | Observer with pinned chain/deployment/trust | First helper checks successful transaction/event; public verifier has stronger source, chain, head and finality requirements | Event receipt alone is not finality | Source inspection only; no reorg qualification in this six-case suite | Reuse qualified observer semantics and add a pre-admission funding gate |

Bare Merkle methods without proof metadata reject. Existing signature release
pays the full remaining amount. Token transfers require exact balance changes;
fee-on-transfer behavior is not made acceptable by an adapter. The first
prototype therefore uses only a zero-decimal mock ERC20, fixed full payment and
an explicitly trusted verifier. No existing verification profile is weakened.

## Deadline counterexample

The executed trace uses a certificate already valid before expiry, a stronger
positive control than merely claiming a timely submission:

| Chain time | Event | Seller paid | Buyer refunded |
| --- | --- | --- | --- |
| 1789344000 | Buyer deposits 100; operator signs; exact release succeeds in `staticCall` | 0 | 0 |
| 1789344100 | Agreed escrow deadline | 0 | 0 |
| 1789344101 | Same release fails `EscrowExpired`; unrelated caller executes refund | 0 | 100 |
| 1789344101 | Same release now fails `EscrowAlreadyRefunded` | 0 | 100 |

`staticCall` establishes pre-expiry eligibility but commits no claim. The
certificate itself contains no certified-at field; the harness records when
it was created. No transaction records that certificate in escrow before
expiry. If work is submitted off-chain before a cutoff but its certificate
arrives after expiry, the same `_ensureLive` failure applies. A local verifier
timestamp cannot postpone an on-chain refund.

The negative calibration sets `CHIO_F1_REQUIRE_TIMELY_CLAIM=1` and asserts the
stronger promise of seller payment 100. It exits 1 with actual payment 0.
The normal characterization suite asserts existing behavior and exits 0.
Keep both results; a green characterization suite does not mean F1 is solved.

## Options and selected route

| Option | What it can establish | Residual authority and timing assumptions | Decision |
| --- | --- | --- | --- |
| Adapter with longer existing deadline | Payment if certification and beneficiary transaction both complete before expiry | Trusted verifier, current registry/key, unpaused admin, bounded chain inclusion before expiry | Viable only as a weaker explicitly named profile; not the selected timely-claim promise |
| Amend existing escrow in place | New pending-claim and resolution rules | Requires compatibility, deployment and security review of every existing consumer | Avoid changing established semantics during this experiment |
| Separate experimental work-claim escrow | Fund agreement; record timely claim; preserve locked amount during resolution; accepted claim remains withdrawable | Trusted pinned F1 verifier/custodian, honest selected rail and explicit inclusion/finality assumptions; unavailable verifier can cause a recorded timeout loss | Selected next slice, with rejection/refund and crash paths tested before native integration |

The next contract must bind the agreement digest, result commitment and
submission event; an accepted financial claim must not expire when a buyer
stops responding or a discovery service disappears. Funding and admission
remain asynchronous: finalized allocation precedes admission, and an uncertain
transaction is reconciled by stable IDs before any replacement is attempted.

## Independently funded child

The sixth test funds A-to-B with 100 and B-to-C with B's separate 60. C receives
60; the parent expires and A receives 100 back. B bears the 60 loss. This
supports separate obligation accounting using existing escrow. It does not
test a child's still-unpaid earned claim surviving expiry, actual useful work,
hostile independent companies, a crash-restarted custody service or a native
kernel/rail composition. Those remain next-slice obligations.

All contracts and five deterministic accounts exist only in memory on chain
31337. There is no RPC listener, deployed-address input or external key input.
Node's native optional accelerators were unavailable on this host and Ganache
used its JavaScript fallback. These tests make no throughput or production
platform claim.
