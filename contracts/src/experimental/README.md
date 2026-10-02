# Experimental funded work claims

`ChioWorkClaimEscrow` is a development-chain prototype of the
[F1 draft](../../../docs/market/open-agent-work/execution/02-contract-draft.md).
It preserves a recorded accepted claim after expiry, including when an
independently funded parent obligation receives a refund. The existing
`ChioEscrow` contract is unchanged.

This prototype has no native funding-admission integration, registered work
wire profile, production custody service, public-chain finality qualification
or independent security review. The verifier is trusted for acceptance and
evidence custody. The contract checks its authorization, not the usefulness of
the work or the truth of off-chain artifacts.

## Run the private-chain checks

Use the unchanged `contracts/pnpm-lock.yaml` and pinned solc `0.8.30`. From the
repository root, after installing the contract dependencies:

```sh
python3 -B -m unittest discover -s examples/funded-work-model -p 'test_*.py' -v
node --test contracts/scripts/work-claim-escrow.test.mjs contracts/scripts/work-claim-model.test.mjs contracts/scripts/funded-work-fit.test.mjs
node contracts/scripts/work-claim-demo.mjs --output /tmp/child-claim-demo.json
```

Each Node process constructs a private in-process Ganache chain, ID 31337,
with deterministic disposable accounts and mock ERC20s. These scripts accept
no external RPC URL, deployed address or account key. The demo exports public
signatures, transaction receipts, events, code hashes and direct balance/state
observations; it exports no signing secrets.

The demo funds A-to-B for 100 and B-to-C for B's separate 60. C's claim becomes
Payable while C still has zero receipts of payment. A's unsubmitted parent is
then refunded. C withdraws after every deadline; A loses 0, B loses 60 and C
receives 60 mock units. Actual checker work and a killed native process are
outside this financial demonstration.

## Terms and authority

`Terms` fixes agreement digest, payer, beneficiary, verifier, token, amount,
submission deadline, challenge-window end, decision deadline and refund time.
All addresses and the agreement digest must be nonzero; payer, beneficiary
and verifier are distinct. Role-address separation does not establish company
independence. Amounts are positive integers at most `2^53 - 1`; deadlines are
strictly ordered and bounded by the same safe-integer ceiling.

Only the payer funds its obligation. The contract derives the allocation ID
as `keccak256(abi.encode(chainId, deployment, terms))`. Uniqueness is scoped
to `(payer, agreementDigest)` so a different payer cannot squat a known digest.
An application must verify the actual funded terms against the jointly signed
agreement before work; an opaque digest alone does not validate that mapping.

Only the beneficiary submits the single nonzero result commitment. Exact
replay acknowledges existing state without changing time eligibility. Any
courier can record a decision signed by the verifier pinned at funding.
EIP-712 binds allocation ID, agreement digest, submitted commitment, decision
digest, accepted flag, beneficiary, token and amount to the chain/deployment.
Malformed and noncanonical ECDSA signatures reject. Existing terms do not
consult a replacement key or a refreshed registry during resolution.

The [fixed ABI vector](../../scripts/fixtures/work-claim-vectors.json) uses
opaque Keccak label digests and decimal-string amounts. It freezes encoding
and signature-domain expectations for the private fixture. It is not an
RFC 8785 work-artifact profile; Task 4 must register and verify that separate
canonical artifact binding before native admission.

## Transitions

| Entry point | Permitted transition and authority |
| --- | --- |
| `fund` | Missing to Funded; payer-only, exact received backing and new-funding configuration |
| `submitClaim` | Funded to Submitted at or before `submitBy`; beneficiary-only; exact retry has no state effect |
| `recordDecision` | Submitted to Payable or Rejected, strictly after `challengeUntil` and at or before `resolveBy`; pinned verifier signature; exact retry has no new event |
| `expire` | Funded/Submitted to TimedOut, strictly after `refundAfter`; permissionless; cannot expire Payable |
| `withdrawPayment` | Payable to Paid; beneficiary-only; no deadline or pause/key-refresh gate |
| `withdrawRefund` | Rejected/TimedOut to Refunded; also expires an unresolved obligation when eligible; anyone may call, recipient remains payer |

Timeout resolves money only. Execution-unknown is not a field this contract
can truthfully resolve. The model retains that independent metadata; native
incident and custody integration is still required.

The immutable admin controls only admission of new funding through pause,
token allowlisting and verifier allowlisting. Those controls cannot revoke
existing claims or change prior verifier pins. A compromised pinned verifier,
unavailable custodian or failing accepted token remains an explicit trust or
availability failure. There is no rescue withdrawal that changes the owner of
a funded claim.

Transfers check exact debits and credits, so a fee, extra outgoing debit,
false return or malformed return cannot consume another claim's backing.
Checks and state effects precede token calls; failure reverts the entire
transition. A reentrancy guard also protects cross-entry callbacks. These
checks assume truthful behavior from the selected token's balance interface;
allowlisting does not turn an arbitrary malicious token into trustworthy money.

## Scope of the evidence

The Python explorer visits 5,508 finite states and 132,192 transitions for two
pre-funded obligations of 3 and 2 units, a fixed actor/input alphabet and nine
ordered timestamps. All 118 exported financial-edge representative traces run
against real bytecode, including exact token-balance checks. This is bounded
testing, not an unbounded proof or execution of every model path on-chain.

The negative control compiles a modified copy in memory only:

```sh
CHIO_CLAIM_MUTATION=expire-payable node --test --test-name-pattern='accepted claim survives' contracts/scripts/work-claim-escrow.test.mjs
```

It must fail because an accepted claim becomes refundable. The legacy escrow's
separate negative calibration remains retained. See the
[execution report](../../../docs/market/open-agent-work/execution/05-claim-escrow-results.md)
for source hashes, exact commands and the still-open native integration gate.
