# Funded claim escrow: executable result

Date: 2026-09-14. Tasks 1-2 of the
[claim-escrow plan](../../../superpowers/plans/2026-09-14-funded-work-claim-escrow.md)
are implemented in the isolated research branch. An accepted child claim can
remain unpaid while its parent is refunded, then withdraw after all deadlines.
The [native integration gate](06-native-integration.md) is still open.

Implementation commits: `cbcb595963` (model) and `640002afb7` (contract,
tests and reproduction). The original paper checkout, active security worktree
and existing escrow semantics are preserved. These are local prototype results, with synthetic
certifications and mock tokens. No deployment or external funds were used.

## What now executes

- [Claim model](../../../../examples/funded-work-model/claim_model.py): exclusive
  paid/refunded/locked accounting, exact retries, acceptance windows, timeout,
  failed transfers, independently funded children and preserved execution-unknown.
- [Finite explorer](../../../../examples/funded-work-model/claim_explorer.py):
  5,508 states and 132,192 transitions, with a retained counterexample when
  accepted work is incorrectly made refundable by expiry.
- [Experimental contract](../../../../contracts/src/experimental/ChioWorkClaimEscrow.sol):
  funded immutable terms, timely commitment, pinned-verifier decision and
  permanent eligibility for an accepted withdrawal.
- [Contract tests](../../../../contracts/scripts/work-claim-escrow.test.mjs):
  actual bytecode, signature/domain substitution, exact backing, deadline
  boundaries, key/pause behavior, competing mined withdrawals and adversarial tokens.
- [Model replay](../../../../contracts/scripts/work-claim-model.test.mjs): all
  118 exported financial-edge representatives compared with actual contract
  state, source/recipient balances and the contract's remaining token balance.
- [Standalone reproduction](../../../../contracts/scripts/work-claim-demo.mjs):
  a public local-chain artifact with observed states, balances, signatures,
  transaction receipts, events and bytecode hashes.

## The financial failure case

The [retained reproduction](claim-evidence/child-claim-demo.json) starts with
1,000 mock units each for A and B, and zero for C. A funds B for 100. B funds
C for 60 from its own balance. The verifier signs a synthetic accepted child
decision before the decision deadline. C has earned a claim but has received
no payment yet.

| Observation | A balance | B balance | C balance | Escrow balance | Child state |
| --- | --- | --- | --- | --- | --- |
| Both obligations funded | 900 | 940 | 0 | 160 | Funded |
| Child accepted, still unpaid | 900 | 940 | 0 | 160 | Payable |
| Unsubmitted parent refunded | 1,000 | 940 | 0 | 60 | Payable |
| Child withdraws after all deadlines | 1,000 | 940 | 60 | 0 | Paid |

The intermediary bears the 60-unit loss. Expected parent revenue never backs
the child. The parent supplies no final output; the demonstration does not
claim that a native parent process was executed and killed. The signed child
certificate is a fixture, not evidence that a useful checker ran.

The demo's actual deployed runtime code hash is
`0x1415ce95a2559f1e05d9ababaee638e13ee61de833f03de2b0cca8940d0c186f`.
It is specific to this compiled source, optimizer/EVM settings and immutable
admin binding. The artifact also records creation-code hash and transaction
gas usage. These local observations are not a public-chain finality proof.

## Fresh verification

The [machine-readable manifest](07-claim-results.json) contains exact commands,
terminal statuses, retained log hashes and final source hashes. Results:

| Check | Result and scope |
| --- | --- |
| Python model/regressions | 18 passed: original allocation tests, new claim tests and positive/negative exploration tests |
| Normal finite exploration | 5,508 states, 132,192 transitions, no modeled safety violation |
| Broken-expiry exploration | Expected exit 1; accepted parent claim refunded after a submit/accept/timeout trace |
| Combined Node run | 143 passed, 0 failed, 0 skipped: 18 claim-contract checks, 118 replay subcases plus their parent check, and six legacy escrow checks |
| Expiry-guard bytecode mutation | Expected exit 1; removing Payable protection allows a refund that the positive test requires denied |
| Standalone financial reproduction | Exit 0; parent refund 100, later child payment 60, intermediary loss 60 |

Representative commands from the isolated repository root:

```sh
python3 -B -m unittest discover -s examples/funded-work-model -p 'test_*.py' -v
python3 -B examples/funded-work-model/claim_explorer.py --output /tmp/claim-traces.json
cmp examples/funded-work-model/claim-traces.json /tmp/claim-traces.json
python3 -B examples/funded-work-model/claim_explorer.py --broken-expiry --output /tmp/claim-counterexample.json
node --test contracts/scripts/work-claim-escrow.test.mjs contracts/scripts/work-claim-model.test.mjs contracts/scripts/funded-work-fit.test.mjs
CHIO_CLAIM_MUTATION=expire-payable node --test --test-name-pattern='accepted claim survives' contracts/scripts/work-claim-escrow.test.mjs
node contracts/scripts/work-claim-demo.mjs --output /tmp/child-claim-demo.json
```

Both negative commands must fail. Normal tests must pass. The new prototype
does not turn the previous escrow-fit characterization into an F1 guarantee
for the legacy contract. Its original deadline counterexample remains valid.

Toolchain: Node 24.16.0, solc 0.8.30, ethers 6.16.0, Ganache 7.9.2, Python
3.13.13 on Linux/aarch64. Solidity optimizer uses 200 runs and targets Paris;
the local chain uses Shanghai. Optional Ganache native accelerators are absent
on this host; its JavaScript fallback executes the selected tests. No contract
dependency, lockfile or compiler-setting change was required.

## Findings resolved during implementation

**An unrelated payer could occupy an agreement digest.** The first prototype
made agreement uniqueness global. A one-unit deposit by X under a known digest
prevented A's valid funding. A regression reproduced that failure. Uniqueness
now includes payer identity; the actual deposit caller must be that payer.
An attacker can fund its own unrelated terms but cannot consume A's allocation
namespace. Application admission must still compare all funded terms with the
joint agreement before work begins.

**The compiler could not hold the full authorization path on its stack.**
The initial signature verifier combined typed hashing and ECDSA decoding in
one function. The pinned compiler rejected it. Separating those internal
operations fixed compilation without changing the encoding, compiler mode or
signature guards. Frozen ABI/EIP-712 vectors and substitution tests now cover
the shared encoding boundary.

**Token return status is insufficient evidence of exact transfer.** The
prototype checks both payer/escrow debits and recipient credits. Tests execute
false, fee-charging, extra-debit, false-after-mutation and malformed-return
tokens; failed transactions preserve the claim and other backing. A token
callback fails the reentrancy guard. The selected token remains trusted to
report balances truthfully; this is not protection against arbitrary malicious
token semantics or administrator powers in an external asset.

The model and contract use distinct implementations. The normal model graph
is finite and already funded; it does not exhaust arbitrary deposits, amounts,
funding races, chain reorganizations or dishonest verifier strategies. Unit
tests cover the selected funding/amount/transfer-failure boundaries separately.
Replay covers 118 edge representatives, not every model path on-chain.

## Remaining vertical-slice work

The new escrow supports the selected monetary rules. F1 also needs a real
agreement parser, native pre-admission funding verification, real predicate
evaluation, retained verifier custody, immutable incident handling and
authoritative post-crash reconciliation. Those are Task 4 requirements on the
reviewed paper/Security M4 candidate, not properties supplied by this prototype.

M4 remains unclosed at `8738bdfd7b`. Task 3 therefore has no qualified source
to integrate yet. No parent/child native crash, cross-company operation,
public-chain finality/reorg, sustained custody capacity or real-funds canary is
claimed. No full milestone or H1-H5 breakthrough verdict follows from this run.
The current source is committed locally for review; remote CI and independent
security review remain outside this execution result.
