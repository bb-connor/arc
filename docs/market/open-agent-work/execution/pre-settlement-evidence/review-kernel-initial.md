# Core, kernel and SQLite execution evidence review

Reviewed worktree: `/home/connor/backbay/arc-funded-integration`.
Base: `df2e7ef0ed1e1ba3ba5ef244e2247347b2c0f3e0`.
HEAD: `ad3dedbf37dfe732771d4458721156fc543fd524`, including the uncommitted execution-evidence implementation read during this review.

No actionable correctness or security defect was established in the reviewed implementation. This is a static review, not an assertion that the delivery gates passed. No Cargo commands, tests, source edits, commits, or external messages were performed.

Reviewed the design, core receipt profile, kernel export coordinator, qualified projection token and source validator, SQLite projection/schema/migration changes, related original-request checks, and checked-in execution tests. Followed the existing admission participant and rollback-anchor implementation far enough to check that the new digest is committed through the existing global authority chain.

## Findings

None with a demonstrated failing execution path in this scope.

The following contracts are represented in the implementation:

- The receipt profile requires an admitted strict signature, explicit execution-only semantics, allow decision, native tool origin, resolved-output commitment, no copied guard-detail claims, and no top-level financial or budget authority.
- The first export requires the retained original request, tenant and authority, a Finalizing operation, a complete native Value outcome, the frozen original signer, exact retained evaluation plan and normalization, resolved canonical bytes, matching guard allow digest, and original hold/authorization identity.
- Identity and signing callbacks run after releasing the mutation sequencer. The original lease and exact retained operation/request are checked after signing, and SQLite reloads the source records and checks fresh time and the same lease inside its write transaction. There is no signer fallback.
- A qualified kernel-only token authorizes the immutable per-operation projection. Its canonical receipt and source commitments are hashed into the admission participant commit, which is covered by the global authority chain and rollback anchor. Source lookup verifies the projection against the latest non-null participant commitment.
- Cached export verifies the original source and current crypto floor and returns the retained canonical receipt without invoking the current signer. Payment identity hashing excludes mutable settlement state while retaining original authorization, hold, amount, currency, rail, and creation identity.
- Receipt materialization appends directly without a settlement-observer job. The export does not dispatch, settle, terminalize the operation, project a final payment receipt, or return resolved output bytes.
- The exact v3 predecessor catalog is checked before migration; existing security-release objects remain included in both predecessor and current schema verification. Unknown execution namespaces and weakened current schemas fail closed. Execution evidence prevents retention compaction of its raw source blob.

## Qualification gaps to close before claiming the full design is proven

These are missing explicit regression witnesses, not reproduced implementation defects.

1. `crates/kernel/chio-kernel/tests/durable_admission_sqlite/execution_evidence.rs:242`: The anchored corruption test deletes only the execution row while retaining its participant commit. Add a separate replacement test with canonical row fields recomputed, and a rollback test restoring the database to before the execution projection, including the corresponding admission participant/global commits, while keeping the newer external anchor. Each must fail opening or reading the authority and must not produce another signature or dispatch. The current SQL trigger tests exercise blocked writes but do not establish the offline rollback claim.
2. `crates/kernel/chio-kernel/src/kernel/tests/durable_admission/execution_evidence.rs:172`: Callback modes cover reentry, time expiry, panic and signer substitution, but do not change the live operation/fence/request/outcome/evaluation/payment identity while signing. Add at least a live claim/fence replacement and source-record mutation witness; each should reject before projection or receipt-log append. This directly qualifies the fresh-source requirement at the signer boundary.
3. `crates/kernel/chio-kernel/src/tool_outcome/execution_evidence.rs:204`: The source validator explicitly rejects caller delivery, security context/release, federation, execution nonces, absent original signer, and incomplete/streaming output, but the new checked-in execution tests do not contain a complete adversarial source-provenance matrix. Add targeted rejection cases, including a fully resolved denied output, and assert no evidence projection, additional dispatch, settlement or observer work.

## Scope clarification

Root confirmed that the first profile intentionally supports complete native `InvocationOutputV1::Value` only. Complete streams are rejected intentionally; the design/report should say this explicitly rather than imply all complete native output forms are supported. Arbitrary ordinary `receipt_context` is also intentionally allowed by the core profile; the kernel producer itself emits only the original request id there.

No defect was filed for the optional informational receipt algorithm field, ordinary receipt-context extensions, or the lack of a streaming export path, since those would conflate the accepted profile with stricter or broader requirements.
