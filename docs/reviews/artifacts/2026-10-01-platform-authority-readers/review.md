# Independent platform review and resolutions

One read-only reviewer (`platform_final_review`) examined the 31 pinned readers,
shared owners and production entry points. Implementation remained inline. The
review found four medium-severity correctness/budget issues and one low-severity
error-custody issue. No second independent review of the fixes is claimed.

| Finding | Implemented resolution | Production-linked control |
| --- | --- | --- |
| R1: the plan handler applied signed numeric restrictions to unsigned tool arguments | Parse the bounded whole document with duplicate-aware unsigned semantics; borrow the original capability subtree and validate its separate native signed contract before kernel evaluation. | `original_plan_arguments_keep_unsigned_float_spellings_without_weakening_capabilities` accepts `0.10` arguments, rejects the same spelling in the capability and rejects duplicate arguments. |
| R2: checkpoint/principal readback imposed external I-JSON limits absent from its native writer | Add a separate bounded native canonical durable decoder, retaining typed byte equality, digest, tenant, aggregate and signer checks. | PostgreSQL checkpoint write/read uses `(1_u64 << 53) + 1`; existing durable corruption and tenant tests remain. |
| R3: direct transparency-state entry points lacked complete pre-hash artifact budgets | Preflight aggregate artifact bytes/count before hashing and validate root graph cardinality at both standalone APIs. | `transparency_inspection_budgets_all_artifacts_before_hashing` exercises the public direct path. |
| R4: runtime graph decoding omitted cardinality limits enforced by the generic verifier | Share the 4096-node/16384-edge gate across runtime, interop, enterprise, trust and minimal graph owners before reference traversal. | The runtime parser accepts a valid graph and rejects 4097 nodes before walking references; the deep generic graph control validates iterative traversal. |
| R5: auxiliary evidence predicates discarded native parser errors while remaining fail closed | Fallible receipt/risk/reference predicates propagate input causes through the shared risk-reference traversal; infallible typed lookups retain one delegating API. | Enterprise and trust-market `original_auxiliary_risk_receipt_preserves_parser_cause` controls start from valid signed bundles, update signed graph commitments and reject duplicated auxiliary receipt fields with redacted diagnostics and native sources. |

The final package campaign and PostgreSQL integration evidence are listed in
[README.md](README.md). Consumer compilation also exposed missing clock-error
mappings in tower/API-protect; those adapters now retain the native clock cause.
The Clippy gate found one existing forbidden direct slice in shared signing
custody; checked access preserves the fixed zeroizing buffer and fail-closed
read while satisfying the existing lint without an exception.

The reviewer did not establish PostgreSQL execution, Firecracker execution,
hosted CI, live-provider behavior or external API compatibility by inspection.
Local PostgreSQL execution is separately qualified by the retained campaign.
Firecracker, live providers, optional backends, hosted and release acceptance
remain outside this batch. Broader semantic signature/error-string migration
remains in the roadmap; this batch repairs original parser-cause custody.
