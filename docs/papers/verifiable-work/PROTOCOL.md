# Work-contract reading guide

This guide specifies how to interpret the implemented experimental profiles;
it does not introduce a new production wire protocol. Use the exact canonical
encodings in `examples/funded-work/PROFILE.md` for artifact-only W0 and the
closed typed native v2 bodies in `examples/federated-work/src/funded_work/` for
native execution. Do not mix these bodies or accept unknown versions.

## Three decisions

1. **Admit:** the receiver's kernel checks locally activated authority and the
   exact original request. Agreement signatures and funding evidence are inputs,
   never permission to install a remote issuer. Admission is local and durable.
2. **Accept:** the chosen verifier checks the agreement, exact input/output,
   checker identity, custody and requested assurance. Missing evidence yields no
   decision; a checked mismatch yields rejection. A receipt about execution is
   not itself a claim that the application result is useful.
3. **Settle:** the selected rail validates the pinned financial signer and exact
   allocation-bound decision. The token and domain are fixed by terms. The rail
   does not rerun the Python checker or parse a native Finding.

Every receiver selects its trust inputs before reading peer evidence. A received
key, endpoint, observer address, checker path or chain description does not
become authoritative just by appearing in a signed packet. Replaying a valid
historical packet does not refresh expired permission.

## Canonical identifiers

- Artifact-only agreement digest: SHA-256 of RFC 8785 canonical agreement body,
  signed by both buyer and provider. Signatures are outside this digest.
- Artifact-only submission commitment: SHA-256 of the complete canonical signed
  submission envelope, including the signed custody receipt.
- Artifact-only decision digest: SHA-256 of the canonical decision body.
- Native agreement digest: SHA-256 of the canonical native v2 agreement body;
  it separately commits the original private request, public policy, authority
  UUID, Finding context, required facets, domain and immutable work terms.
- Allocation ID: Keccak-256 of Solidity ABI encoding of chain ID, escrow address
  and complete Terms. A SHA-256 digest used as bytes32 is not rehashed as its hex
  text and is not silently replaced with Keccak-256.
- Financial signature: EIP-712 domain `ChioWorkClaimEscrow`, version `1`, chain
  ID and contract address; `ChioWorkDecision` commits allocation ID, agreement
  digest, commitment, decision digest, accepted flag, beneficiary, token, amount.

The implementation bodies, parsers and malformed-input vectors are part of the
source inventory. Hash algorithms and signed preimages are protocol elements.
A conceptual tuple in the paper is not a parser grammar.

## Financial transition table

| Operation | Precondition | Effect |
| --- | --- | --- |
| Fund | Payer authorizes exact immutable terms; allowed token/verifier; positive amount; future ordered deadlines; unused payer/agreement | Exact token debit and escrow credit; `Funded` |
| Submit | Beneficiary; nonzero commitment; `Funded`; at or before submission deadline | First immutable commitment; `Submitted` |
| Record accept/reject | Pinned verifier signature over exact allocation and commitment; `Submitted`; after challenge and at/before resolution deadline | `Payable` or `Rejected` |
| Expire | `Funded` or `Submitted`; strictly after refund deadline | `TimedOut` |
| Withdraw payment | Beneficiary; `Payable`; exact token debit and credit | `Paid`; no expiry or new verifier-registry check |
| Refund | `Rejected`, `TimedOut`, or legally expired unsettled state | Exact transfer to fixed payer; `Refunded` |

Exact submission/decision acknowledgments are idempotent; changed bytes fail.
Payment/refund transfers cannot repeat. Failed transfers revert the complete
financial transition. This assumes honest allowed-token behavior; observations
of balances cannot defend against arbitrary malicious balance reporting or later
issuer seizure. Local budget/nonce transitions and chain transfers are not a
single distributed transaction.

A recorded accepting decision, under the selected finality rule, creates the
profile's earned payment right. Off-chain completion, an unrecorded signed
certificate, or a model's belief that the task succeeded does not create it.
An unavailable verifier can cause a working provider to miss the decision
window. This is a disclosed residual loss, not a solved fair-exchange problem.

## Failure matrix

| Event | What remains true | What is not established |
| --- | --- | --- |
| Payer forks its own journal | The selected external rail owns exclusive allocations | Payer solvency outside this rail |
| Provider dies before a known return | Original native operation and unknown terminal remain | Whether an external tool effect happened |
| Response lost after durable decision | Original signed decision can be recovered | Fresh authority to repeat execution |
| Parent refunds after child earned | Child's separate allocation stays payable | Child liveness if token/chain/key fails |
| Verifier unavailable before recording | No invented acceptance or rejection; deadline rules still apply | Payment for all actually performed work |
| Observer sees a reorganization | Fresh authority must reobserve or refuse | Finality from a signed local observation alone |
| Registry pauses or changes verifier | Existing immutable earned terms remain in the Chio experimental escrow | Equivalent admin behavior in every alternative rail |

No actor may silently convert an uncertain execution into no effect to release
funds. A separately authorized waiver describes a new financial event and
preserves the earlier history. The research implementation exercises particular
waiver and recovery paths; it does not specify arbitrary subjective arbitration.
