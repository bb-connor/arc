# Execution Evidence and Payment Successors

This is a normative supplement to [PROTOCOL.md](PROTOCOL.md), section 6.2.
These profiles have separate authority domains. An execution statement MUST NOT
be accepted as a spend receipt, a payment authorization, or renewed dispatch
authority. A monetary successor MUST NOT change the original execution result.

## Pre-settlement execution receipt

`chio.pre_settlement_execution.v1` is an execution-only receipt profile.
The verifier MUST authenticate the receipt's canonical signing body with strict
signature verification and require its kernel key in the receiver's independently
admitted key set. A valid signature from an unadmitted key is insufficient.

The receipt MUST have kind `mediated_decision`, boundary `prevent`, trust level
`mediated`, origin `chio_internal`, an allowed decision, and redaction mode `none`.
It MUST NOT carry an observation outcome, actor-chain entries, detached evidence,
or BBS projection/signature. Its action parameter hash MUST verify.

The top-level metadata object accepts only `execution_evidence`,
`receipt_semantics`, `receipt_context`, and `chio_receipt_signing_nonce`. The first two are
required. `receipt_semantics` is the closed object
`{"profile":"chio.pre_settlement_execution.v1"}`. Financial authority keys,
including `financial`, `budget_authority`, `execution_nonce`, `mediated_spend`
and `spend_authority`, MUST be rejected even when their values are null.

`execution_evidence` is a closed object with exactly these string fields:

| Field | Constraint |
| --- | --- |
| `schema` | `chio.execution_evidence.v1` |
| `phase` | `execution_confirmed` |
| `authority_uuid`, `operation_id`, `request_id`, `hold_id`, `authorization_id` | Nonempty, at most 512 UTF-8 bytes, no NUL byte |
| `request_binding_hash`, `request_sha256`, `outcome_id` | Exactly 64 lowercase hexadecimal characters |
| `raw_outcome_sha256`, `resolved_output_sha256` | Exactly 64 lowercase hexadecimal characters |
| `post_return_evaluation_sha256`, `post_guard_decision_sha256`, `pricing_verdict_sha256` | Exactly 64 lowercase hexadecimal characters |

`resolved_output_sha256` MUST equal the receipt's `content_hash`. If
`receipt_context` is present it MUST be an object; its optional `request_id`
MUST equal the execution block's request ID. An optional `chio_receipt_signing_nonce` MUST
satisfy the same identifier constraint. Duplicate keys and unknown fields in
the closed objects MUST reject. The receipt authenticates the admitted kernel's
statement; it does not establish source-store availability, output release,
financial exposure, or settlement.

The local `chio.execution-evidence-projection.v1` record is a closed snake_case
object with `schema`, `operation_id`, `receipt_canonical_json`, `outcome_sha256`,
`payment_identity_sha256`, `recorded_at_unix_ms`, and `store_fence`. Its total
canonical encoding and embedded canonical receipt are each bounded to 1 MiB.
Decoding MUST require exact RFC 8785 re-encoding equality. This is a retained
projection, not a live mutation permit. First export requires `Finalizing` and
the original request, raw outcome, post-return evaluation, resolved output,
payment identity, signer and store fence. Revalidation MUST compare all those
source commitments; a decoded projection alone cannot recreate authority.

## Explicit payment successors

Both families below use closed camelCase objects, RFC 8785 canonical JSON,
strict signatures, and receiver-configured keys. Public keys and signatures use
the existing Chio encodings. A request MUST NOT choose its own trusted policy.
Integers are nonnegative JSON safe integers, bounded above by `2^53 - 1`.
Digests are SHA-256 of canonical JSON, encoded as 64 lowercase hexadecimal
characters. Signed bodies are bounded to 256 KiB. These remain opt-in profiles;
an implementation that does not implement them MUST reject them as unsupported.

### Mutually agreed release of an unknown hold

The policy contains `receiverKey`, `counterpartyKey`, `rail`, and `currency`.
The keys MUST be distinct and non-weak. The rail is a nonempty printable ASCII
identifier of at most 512 bytes, other than `unspecified`; currency is three
uppercase ASCII letters.

The terms contain `schema` (`chio.unknown-payment-release.v1`), `policyDigest`,
`operationId`, `terminalProjectionDigest`, `incident`, `capability`,
`authorizedJournal`, `issuedAtUnixMs`, and `expiresAtUnixMs`. `incident` is the
original signed terminal admission projection. A proposal contains `body` and
`receiverSignature`; the co-signed object contains `proposal` and
`counterpartySignature`. Each signature covers the literal UTF-8 prefix
`chio.unknown-payment-release.v1`, NUL, the role (`receiver` or `counterparty`),
NUL, and the canonical terms bytes.

Verification MUST bind the original receiver-signed terminal projection,
operation, capability issuer and subject, capability artifact digest, request,
namespace, hold and the exact authorized payment journal. The operation MUST
be a tool dispatch in `OutcomeUnknownAfterDispatch`, have no known tool outcome,
and retain the broker, budget and payment participants required by this profile.
The original journal MUST be `Authorized` in the pinned rail and currency.
The capability MUST have no delegation chain and its signature MUST verify.
Terms must satisfy `0 < issuedAt <= trustedNow < expiresAt`, must be issued no
earlier than the incident's trusted time, and span at most 86,400,000 ms.

The qualified store commits the successor before calling the rail. The successor
fence MUST name the same store UUID and either exactly equal the retained fence
or have a strictly greater positive owner epoch. Reusing an epoch with a changed
lease is forbidden. Retries resume the original successor identity. A completed
`chio.unknown-payment-release-receipt.v1` export contains `schema` and `record`
inside the existing signed export envelope. Its receiver signer, pinned policy,
both consents and completed record MUST verify. The execution remains unknown;
this release does not assert non-execution or erase an irreversible effect.

### Contractual capture waiver

The policy additionally pins `observationKey`. Before admission, both parties
sign terms containing `schema` (`chio.contractual-capture-waiver.v1`),
`policyDigest`, `contractContextDigest`, `capabilityDigest`, `requestId`,
`issuedAtUnixMs`, and `expiresAtUnixMs`. The signed terms object contains `body`,
`receiverSignature`, and `counterpartySignature`. Signature preimages use the
schema, NUL, role, NUL, canonical body, as above. The terms' digest MUST be bound
in the original request under `chio_capture_waiver_terms_digest`; later terms
cannot replace it. The original interval is positive and at most one day.

The observation body contains `termsDigest`, `operationId`, `journalDigest`,
`rawOutputDigest`, `contractContextDigest`, `agreementDigest`, `allocationId`,
`refundReference`, `evidenceDigest`, and `observedAtUnixMs`. Its `signature` uses
role `observation` under the locally pinned observer key. The request consists
of `terms` and `observation`. The observer MUST establish external refund
finality and exact funding context; unsigned RPC data is insufficient.

Qualification MUST compare every observation binding with the original retained
terms and native source records. It requires a known output in `Finalizing`, a
reversible hold, and a positive capture pending in `Settling` or
`ReconcileFailed` with no transaction ID. Terms must predate journal creation;
`journal.createdAt <= observedAt <= trustedNow < terms.expiresAt`. A backdated
observation cannot revive expired terms. The store commits a fenced `Resolving`
successor before rail action and reaches `Resolved` only on confirmed release.
The journal release authority is `ContractualCaptureWaiver`; an agreed unknown
release uses `MutuallyAgreedUnknown`. Both require their own retained evidence.
An ordinary cancellation has neither authority.

A completed waiver projects a successfully `settled` receipt with charged
units zero and the original positive realized/budget cost. It MUST NOT be
projected as a payment failure, failed execution, refund of native budget, or
permission to execute again. Fencing, idempotent rail identity and historical
evidence remain required throughout recovery.

## Withheld output

The signed terminal denial vocabulary includes `OutputGuardRejected`
(`output_guard_rejected` on the wire). For the checked output-contract profile,
the retained verdict binds the exact post-transform output and policy. A
qualifying rejection withholds output and permits the specified zero-charge
financial successor. An ordinary guard error before raw-outcome retention leaves
the dispatch committed; recovery preserves uncertainty and its hold. An ordinary
post-transform denial retains the known return and hold in `Finalizing`. Startup
claims that quiescent operation under the current serving fence without blocking
unrelated admissions; a store, version or fencing failure still fails closed.
Neither path authorizes a second dispatch. Historical output-contract validation may use
the original signed permit interval; fresh admission still requires live
authority and current release requirements.

Implementations and conformance anchors:
[execution receipt](../crates/core/chio-core-types/src/receipt/execution_evidence.rs),
[unknown release](../crates/kernel/chio-kernel/src/payment/unknown_release.rs),
[capture waiver](../crates/kernel/chio-kernel/src/payment/contractual_resolution.rs),
and [terminal replay](../crates/kernel/chio-kernel/tests/durable_admission_sqlite/contractual_resolution.rs).
