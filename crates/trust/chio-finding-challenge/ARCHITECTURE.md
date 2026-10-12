# chio-finding-challenge architecture

## Responsibility and boundary

`evaluate_finding_challenge` owns pure adjudication of one signed challenge.
`FindingChallengeEvaluationInput` borrows the raw finding, signed profile,
retained authority policies, authenticated status readings, and class evidence.
The returned `FindingChallengeEvaluation` is either `Inadmissible` or an
`Adjudicated` value with a typed facet and reason.

The caller resolves and retains evidence, authenticates the admission that
supplies pins, and provides trusted evaluation time. This crate owns no store,
clock, network client, replay runner, signing key, or settlement implementation.
A result becomes an outcome artifact only through the coordinator's signing
and enforcement path.

## Structure

| Module | Responsibility |
|--------|----------------|
| `evaluate` | Entry preconditions, role separation, class dispatch |
| `input`, `reason` | Borrowed evidence, rejection vocabulary, derived verdicts |
| `ingress` | Bounded strict canonical finding and attachment decoding |
| `standing` | Purchase-record bindings and settlement standing |
| `audit` | Governance-authorized committed audit selection |
| `receipts`, `revocation` | Role lifecycle, references, authenticated withdrawal |
| `digest_mismatch` | Failed-delivery terminal and seller output commitment |
| `evidence_invalid` | Contested production evidence and checkpoint anchoring |
| `replay_contradiction` | Committed recipe, reproduction observations, predicate |

## Data and control flow

1. Reverify the signed challenge and reject evaluation before its filing time.
2. Verify the governance profile, retained governance policy and status, role
   independence, and both admission and challenge profile digests.
3. Strictly parse bounded canonical finding bytes, verify the artifact, and
   cross-bind its digest and identifier to the challenge.
4. Enforce the closed challenge/finding compatibility matrix. Venue audits
   additionally require the authenticated committed draw artifacts.
5. Select exactly one evidence branch; cross-class evidence is inadmissible.
6. Produce a reason-derived facet and verdict for downstream outcome signing.

Digest mismatch uses the signed failed-delivery terminal as standing and checks
receipt/checkpoint evidence for the finding's identity output profile.
Evidence invalidity anchors the contested bytes before treating a signature or
semantic contradiction as affirmative fraud. Replay contradiction checks the
recipe preimage and completed baseline/candidate observations against their
receipt content hashes before computing the committed predicate.

## Trust and invariants

A signed submission cannot select its own admission profile or lifecycle pins.
Authority-status signer separation prevents a trusted market role from
self-attesting standing. Purchase and failed-delivery authority policies come
from the exact retained admission, including admission-specific rotations.

`FindingChallengeReason` separates affirmative fraud, clean evaluation, and
unestablished inputs. Its verdict mapping supplies `Upheld`, `Rejected`, and
`Indeterminate`; the adjudication constructor is private. A timeout, incomplete
run, or unresolved authority cannot become a sanction through a caller-set
verdict. `authorizes_penalty` is a local result predicate; the coordinator must
still authenticate, sign, bind, and apply the outcome.

Canonical raw ingress rejects duplicate members, unknown fields, oversized
attachments, noncanonical bytes, and typed serialization drift. Historical
publication evidence is evaluated against retained policy and authenticated
lifecycle readings, with the supplied evaluation time bounding freshness.

## Dependencies

`chio-finding` supplies artifact types, strict envelope verification, and the
compatibility matrix. `chio-finding-verifier` supplies strict receipt and full
checkpoint membership checks. `chio-kernel` supplies checkpoint types;
`chio-open-market` supplies committed audit-selection and purchase evidence.
`chio-core-types` supplies canonical bytes, signatures, and receipt metadata.

## Verification

Run `cargo test -p chio-finding-challenge` from the workspace root.
`tests/admission.rs` covers role collisions, retired profiles, rotated purchase
authorities, standing bindings, and audit draw selection. The three class test
files cover delivery overlays, checkpoint anchoring, revoked keys, recipe
binding, incomplete reproductions, and reason/verdict classification.
The README wrapper requires a caller-supplied complete input to adjudicate;
its offline assertions exercise reason mapping only.
