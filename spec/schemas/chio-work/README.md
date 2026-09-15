# Experimental native funded work

These four registered envelopes describe the bounded one-host, private-chain W0
profile implemented in `examples/federated-work/src/funded_work`. They do not
establish public finality, remote operator isolation or full evidence backing.

| Identity | Signed authority |
| --- | --- |
| `chio.experimental.native-funded-w0-agreement.v2` | Buyer and provider commit the original policy, request, funding domain, terms, exact pre-provisioned Finding context digest and ordered required facets. |
| `chio.experimental.native-funded-submission.v1` | Provider binds the original allocation, agreement, authority, operation, hold, authorization, request and native return to input/output digests and an existing `chio.finding.v1` artifact. |
| `chio.experimental.native-funded-dependency.v1` | Parent provider binds independently funded parent and child agreements, requests, authorities and shared input. |
| `chio.experimental.native-funded-decision.v2` | Pinned verifier binds the original submission commitment, custody binding, checker, claim transaction/block and complete Finding assessment. |

Agreement v1 and decision v1 are historical example encodings. They are not
registered by this change and cannot authorize the new acceptance path. Submission
v1 and dependency v1 retain their existing valid byte encodings. Nested waiver
terms retain the existing `chio.contractual-capture-waiver.v1` contract and exact
receiver/counterparty signatures; they are not arbitrary extension objects.

All envelopes require raw-first duplicate-key rejection, exact canonical typed
JSON and a 256 KiB limit. Omitted optional fields cannot be `null`. Integers are
bounded by 9007199254740991; the amount uses canonical positive decimal notation, at most 16 digits,
and is additionally checked against the same safe integer maximum. The current
local chain profile is pinned to chain 31337. Hashes and
Ed25519 keys/signatures use exact lowercase hex; chain hashes and addresses have
an explicit lowercase `0x` prefix. Free identifiers are at most 512 UTF-8 bytes
and exclude whitespace and control characters.

The agreement and effective assessment require artifact integrity and guarantee
consistency. Facet lists preserve `FindingFacetKind::ALL` order and uniqueness.
The decision retains all thirteen ordered results from the existing Finding
verifier. Schemas reuse the registered Finding artifact and verifier facet-result
schemas. Shape validation does not verify a signature, context, claim, authority,
facet derivation, original custody or funding fact. The verifier must recheck
those bindings and the Finding's claim-derived facet floor. A failed optional
facet still rejects. Unavailable or unsupported required evidence cannot mint a
positive or negative financial decision; the original timeout/refund path applies.

## Relationship to market artifacts

The bilateral funded agreement is the W0 admission contract, not a replacement
for market bid/ask/acceptance. The submission transports an existing Finding;
it is not a verified-fix submission or proof of repair. The decision is a bounded
funded-work acceptance result, not a purchase record/result, reimbursement claim,
challenge outcome, market admission or verifier report. Dependency preserves
separate funded authorities and does not grant broader delegation or commerce
rights. Those market roles retain their existing registered artifacts and
independent authority checks; this profile does not implement them.

Run `bash scripts/check-chio-schema-registry.sh` for registry/manifest parity and
`python3 scripts/tests/check-registered-work-schemas.py` for offline schema shape
regressions. The latter uses `jsonschema` and `referencing`; it deliberately uses
synthetic signatures and does not claim cryptographic verification. The funded
work shared vectors and Rust/Python raw parsers provide the separate wire and
signature-boundary checks.

Current Rust, TypeScript and Python SDK code generators select
`spec/schemas/chio-wire/v1`. This independent schema family requires no generated
SDK changes. Do not broaden that input root solely to create generated churn.
