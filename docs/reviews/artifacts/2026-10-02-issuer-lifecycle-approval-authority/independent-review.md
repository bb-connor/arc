# Independent review: issuer lifecycle and approval authority

Reviewer: `lifecycle_approval_final_review`, read-only, one pass over the uncommitted
batch based on `a617c0b02f182afac6acab2df89a2cd9270e4923`. No Rust or Cargo commands,
source mutations or additional review agents. The affected-owner campaign was
still running; the review did not classify it as passing.

Initial verdict: **not ready to merge**. Three Important consumer gaps were
confirmed and accepted for correction. No Critical findings were reported.

1. **Portable verdict omits issuer lifecycle validation.** Full admission invokes
   `check_issuer_lifecycle`, while `validation/portable.rs` only supplies trusted
   keys to the portable core. A post-rotation issuance can pass during grace; a
   static CA pin can bypass retirement. Apply the same current issuer/time hook
   and cover issuance cutoff, overlapping static pins and clock failure.
2. **Broker-host keyring retains an obsolete trust snapshot.**
   `process_host/keyring.rs` copies `witnessed_verification_keys` into
   `ParentAuthority`. A retained host misses later deadlines and retirement or
   revocation. Resolve live witnessed state at each admission and exercise the
   retained host across those changes.
3. **MCP execution bypasses persisted approval decisions.** Raw signed intent and
   token metadata reaches the kernel without consulting `remote_operator_approvals`.
   A roster-signed approval can execute while its record is Pending or Denied, or
   despite expired pending-record authority. Require the exact retained Approved
   record and token before the remote-MCP call reaches dispatch; test direct
   signed metadata in each rejected state and require zero upstream calls.

The reviewer found no delegated-root variant of the first issue in signed-lineage
verification: signed ancestors retain `token.issuer`, and child issuance cannot
precede parent issuance.

Strengths noted: lifecycle transitions derive the complete signed state, recovery
pins are immutable and recovery-root promotion rejects; SQLite custody checks
ownership, modes, sidecars and file identity before seed writes; API-protect binds
the persisted request and revalidates it before durable admission.

## Scope rulings

The reviewer declined to judge the following as outside the approved source
batch. The executor accepts each boundary and keeps it explicit in the execution
record rather than treating it as completed work:

- Non-Linux custody, pending equivalent ACL/descriptor qualification.
- Encryption and HSM protection; this design retains plaintext filesystem custody.
- Automatic recheckpointing, repinning and seed transfer, which require operator
  procedures.
- Independent per-token revocation; current capability and approver authority
  withdraw the grant instead.
- Hermes execution resume and the legacy Docker workflow, which remain unavailable.
- Hosted CI, release, deployment and operational migration.

These limits did not independently block the reviewed source batch. The three
consumer gaps did. Final dispositions and terminal controls must be recorded
before this initial verdict is considered resolved.

## Correction evidence

The original three findings each received four production-consumer controls.
`independent-review-consumer-red-3` reproduced all twelve failures.
`review-fixes-session-scope-red-2` passed all twelve after the fixes. That combined
run still exited 101 because of separate kernel fixture/session controls, so it
does not establish a passing owner campaign.

The reviewer accepted the original three source corrections:

- Full and portable admission share the issuer lifecycle hook, before trust-set
  resolution. Static pins cannot override managed lifecycle state.
- Retained CLI hosts resolve current witnessed state and owned time on admission.
  Historical evidence verification remains separate.
- Shared MCP session ingress checks the exact signed retained Approved record and
  token before forwarding the call, including native consumers.

The follow-up identified one further Important issue in the new session repair:
using only `tenant:{tenant}` for authenticated sessions omitted the owned session
identity. The same agent could present the held artifacts in another session of
that tenant. Durable tenant namespacing did not supply a mandatory session fence.
`same-tenant-session-red` reproduced the new control failing while the preceding
four session controls passed. Its terminal exit was 101.

The correction canonicalizes the structured schema, owned session ID and optional
authenticated tenant ID, then binds their SHA-256 digest into the signed intent.
The same helper validates retained retries, fresh session presentations and raw
entrypoints.

Final source-review disposition: **accepted**. The reviewer confirmed the
same-tenant correction and the actual two-OAuth-session regression control, with
the original three fixes still accepted. No new blocking regression was found.
The reviewer made no claim about the then-running final build, owner suites or
lint. Their terminal results belong to the execution record and qualification
manifest. Hosted, release and operator acceptance remain outside this review.
