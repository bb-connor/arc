# Experimental funded W0 artifact profile

Status: example-local implementation, 2026-09-14. These names are deliberately
separate from native Finding profiles. Registry, public SDK and native admission
integration remain unqualified. The [F1 draft](../../docs/market/open-agent-work/execution/02-contract-draft.md)
is the wider target; this implements its artifact-only subset.

## Encoding and signatures

Signed bodies use RFC 8785 canonical JSON and Ed25519. Agreement envelopes have
exactly `body`, `buyerSignature` and `providerSignature`; both signatures cover
the identical canonical body. Other signed envelopes have exactly `body`,
`signerKey` and `signature`, using the existing Python buyer primitives. Locally
configured pins select the accepted signer; an envelope cannot introduce a key.

SHA-256 hashes are 64 lowercase hexadecimal characters. EVM bytes32 values
prefix 64 hexadecimal characters with `0x`. Addresses have `0x` plus 40 lowercase
hexadecimal characters. Nonzero identities are required. Monetary amounts and
chain IDs are unsigned canonical decimal strings, positive and at most
`9007199254740991`. Timestamps are integer seconds within that same bound;
booleans do not count as integers. All deadline inequalities are strict in the
agreement: submission, challenge, resolution, refund.

Wire input is UTF-8, at most 256 KiB per parsed envelope/request and 16 nested
containers. Duplicate keys, nonfinite numbers, unpaired surrogates, unsafe
integers and unsupported artifact fields/versions are denied. W0 input/output
bytes are each at most 64 KiB. Input/output hashes cover their exact raw bytes;
comparison of the parsed output uses canonical JSON. Input need not arrive with
canonical whitespace. Unsupported OpenAPI semantics follow the existing
bounded declaration checker, not a general OpenAPI validator.

The executable grammar is [artifacts.py](artifacts.py); frozen positive and
malformed encodings are in [parser-vectors.json](parser-vectors.json). These
vectors use public test identities, never operational keys.

## Exact bodies

| Schema suffix, under `chio.experimental.` | Exact body fields |
| --- | --- |
| `funded-w0-agreement.v1` | `schema`, `workId`, `buyerKey`, `providerKey`, `verifierKey`, `custodianKey`, `inputSha256`, `checkerSha256`, `assurance`, `parentAgreementSha256`, `rail`, `deadlines`, `custody` |
| `funded-w0-output.v1` | `schema`, `operations` |
| `funded-w0-custody.v1` | `schema`, `agreementSha256`, `inputSha256`, `outputSha256`, `policy`, `retainUntil` |
| `funded-w0-submission.v1` | `schema`, `agreementSha256`, `allocationId`, `inputSha256`, `outputSha256`, `checkerSha256`, `custody` (signed receipt) |
| `funded-w0-decision.v1` | `schema`, `agreementSha256`, `allocationId`, `commitment`, `inputSha256`, `outputSha256`, `checkerSha256`, `custodyReceiptSha256`, `retainUntil`, `retentionPolicy`, `assurance`, `accepted`, `predicate`, `rail` |

`rail` contains exactly `chainId`, `escrow`, `runtimeKeccak256`, `token`, `payer`,
`beneficiary`, `verifier`, `amount`. `deadlines` contains exactly `submitBy`,
`challengeUntil`, `resolveBy`, `refundAfter`. `custody` in the agreement contains
exactly `policy`, `retainUntil`. `workId` has 1..128 ASCII letters, digits,
underscores or hyphens. Parent digest is either null or a nonzero SHA-256 digest.
It does not itself grant disclosure or delegation authority.

The four Ed25519 roles are distinct within each agreement. In the child
fixture, the parent's provider key becomes the child's buyer key and a third
party supplies the child provider key. The corresponding EVM parties are A to B
and B to C, with the child paid from B's already held mock tokens.

`assurance` is only `artifact-only-v1`. No native facet map is accepted. The
checker digest is the SHA-256 of the canonical [checker profile](checker-profile.json),
which pins existing Rust/Python source and Python parser bytes. The verifier
checks its Python source pins before evaluation. The Rust command supplies
observations; the verifier independently recomputes them in Python. Both
implementations and all fixture roles remain administered by this project.

Each operation has exactly `path`, `method`, `authenticationRequired`; only
supported HTTP methods, slash-prefixed paths of at most 256 UTF-8 bytes and
boolean outcomes are accepted. There are 1..512 observations. The predicate
requires the complete sorted list to equal the independently computed result.
It inventories declarations, not the security of a deployed API.

## Custody and decision

The custody policy is `local-retain-indefinitely-v1`, with a signed minimum
`retainUntil >= refundAfter + 2592000`. There is no deletion/GC API or finite
expiry in this store. The prototype retains input, output, agreement body,
custody receipt, submission and decision under immutable content hashes. A
claim or decision cannot replace an earlier value for its allocation. Exact
retries return the original authority, including after reopening SQLite.

Storage uses FULL-synchronous SQLite transactions and readback. Files must be
owned, regular, mode 0600 and singly linked; the immediate parent must be an
owned mode-0700 directory. Symlink files are denied. Limits of 64 retained claims
and 16 MiB of object bytes deny additional evidence without evicting old claims.
These are finite experiment limits, not trial capacity or the kernel's retention
implementation. Host administrators, filesystem availability and backups remain
trusted; there is no clone/rollback protection or remote access service here.
The signed policy expresses an obligation, not proof of 30 days of availability.
Test fixtures deliberately remove their throwaway state on completion. The
standalone command retains its state for operator-controlled custody.

Before acceptance the verifier validates joint authority and submission,
retrieves exact input/output and the signed receipt, reruns the checker, and
persists the submission/decision before releasing the result. Wrong output gives
`accepted: false`, `predicate: mismatch`. Missing/tampered custody, authority or
checker inputs give no financial decision. A match gives `accepted: true`,
`predicate: match`. There is no challenge adjudicator in this profile.

## EVM binding

The escrow's `agreementDigest` is SHA-256 of the canonical agreement **body**.
The on-chain `commitment` is SHA-256 of the complete canonical **signed submission
envelope**, including its custody receipt. `decisionDigest` is SHA-256 of the
canonical decision **body**. They are passed as bytes32, without hashing the hex
text or silently replacing SHA-256 with Keccak-256.

The separate EIP-712 domain is `ChioWorkClaimEscrow`, version `1`, chain ID and
escrow address. `ChioWorkDecision` binds allocation ID, agreement digest,
commitment, decision digest, acceptance, beneficiary, token and exact amount.
The existing contract checks the pinned EVM verifier signature. The example's
signing helper receives only the Python-authorized body and checks it against
actual submitted contract state before signing with the private-chain key.
All artifact and EVM keys share one host in this demonstration.

A trusted local observer supplies actual chain ID, contract code hash, state,
terms, commitment and timestamp. Authorization requires the exact joint terms,
`Submitted` state and `challengeUntil < chainTime <= resolveBy`. This is not a
finality proof. The integration harness also reconstructs balances from actual
ERC20 transfer logs and compares paid/refunded state with escrow outflow.
Native pre-admission and unknown-payment reconciliation remain separate work.
