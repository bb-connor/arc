# PR 1173 formal source reconciliation

The production-readiness review reconciles the source anchors after integrating
the security prerequisite from `main` at
`4f3c967f04af40b5025b9222e8db95a3aee0b5f4`.
The drift included earlier changes already present in this branch. The review
compared the 108 Rust files reported by the mirror checker against
`ce36ef0b29`, before the funded-work integration, and checked the current
implementations behind relocated wrappers.

## Review disposition

- Core: checked indexing, duplicate-aware canonical decoding and private
  capability accessors reject malformed inputs. Merkle traversal retains its
  carry-last and exact-path rules. The proof fixture now quantifies directly
  over every bounded path, including arbitrary hash bytes, and keeps the
  independent traversal model and unwinding checks.
- Runtime: receiver custody intersects the resolved deadline with the original
  authority. Graph lookup binds the exact signed graph hash. Native output uses
  the strict reader. Taint observation becomes `Top` on overflow; the admission
  boundary still rejects overflow. Clock acquisition propagates failure.
- Kernel: retained request v4 requires an authority profile at decoding, which
  makes the removed optional-profile checks redundant. Caller start authority
  freezes the minimum credential and runtime deadline before capture; replay
  cannot refresh it. Approval and DPoP acquisition retain their original
  conditional ownership. Checked-output denial and delivery mismatch bind
  redacted receipt content. Unknown effects retain conservative recovery and
  settlement dispositions.
- SQLite: native state validates the initialized authority, record identity,
  mutation digest, exact global commit, lease and owner epoch. Ordered history
  traversal performs the exact-reference checks formerly duplicated by nonce
  coverage scans. Transaction time checks use the serving owner. Outcome
  projection verification checks the canonical blob, operation, evaluation,
  security release, execution evidence and latest participant commitment.
  Receipt append still validates duplicates and its unified commit sequence.

## Anchor repairs

The retired legacy-nonce file is removed from the source inventory; the current
operation-owned nonce preflight remains anchored. Checkpoint construction,
receipt append and outcome projection anchors follow the moved implementation
and include its validating helper. Deadline freezing, credential expiration,
retained-request schema and cumulative approval, checked-output visibility, and
initialized record validation are now explicit symbols. Native policy schema
constants follow their canonical security-types definition.

The checked-in hashes are regenerated only after this review. Both the mirror
checker and generated proof-coverage inventory must pass on the final source.

## Proof boundary

These entries remain `abstraction_anchor` relationships. The PostAdmissionDropGuard
model checks bounded resource conservation, terminal receipt accounting, child
flush ordering and conservative retention. RevocationPropagation checks its
bounded revocation model under the stated fairness premise. Neither proves Rust
refinement, TLS, SQLite durability, wall-clock availability or arbitrary process
execution. The source review preserves that distinction. Executable regressions,
Kani results, mutation controls and native crash qualification provide separate
evidence for their respective implementation boundaries.


## Authority-signature review extension

The review repair replaces compatibility Ed25519 verification with the existing
strict verifier at consent, terminal-evidence, directory admission, bilateral
receipt/DSSE, trust enrollment, FROST artifact authority and fanout boundaries.
It does not change signed preimages, the native threshold-group verifier, or
any proof premise. Weak configured payment, oracle and FROST artifact keys are
rejected before they can establish authority. The A2A change preserves typed
and wire errors while projecting successful task results. Recheck the existing abstraction
anchors and regenerate the coverage input digest after this reviewed source
change. These hashes continue to record review, not Rust
refinement or cryptographic proof.
