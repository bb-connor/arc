/-
  Comparison-set completeness for cross-organization admission.

  The receiver of a co-signed bilateral statement decides a call by comparing
  fields of that statement against values it already holds. This module makes
  the set of those comparisons a closed object: `Field` enumerates every leaf
  the wire type can carry, `classify` assigns each leaf exactly one
  classification, and `accept` is the conjunction of the comparisons the
  classification names. Totality is structural rather than asserted, because
  `classify` is a match on `Field`: a leaf added to the statement adds a
  constructor, and the match does not elaborate until the new leaf is
  classified.

  What the theorems below establish, over this model:

  * every leaf falls into exactly one of three kinds: bound to a named
    receiver-held value, constrained only against the statement itself, or
    constrained by nothing;
  * acceptance holds exactly when every bound leaf equals the receiver-held
    value it names, so no further gate and no hidden gate can carry it;
  * acceptance therefore implies the binding claim field by field, and a
    single disagreeing bound leaf denies;
  * acceptance is a function of the bound leaves alone, so the leaves the
    classification marks unbound are exactly the residual an adversary who can
    produce both signatures may choose freely.

  What they do not establish. The classification is a model of the receiver's
  checks, not an extraction of them: nothing here proves that the shipped
  admission hook realizes this table. That link is carried by the executed
  substitution corpus in
  `crates/kernel/chio-runtime-core/tests/runtime_treaty_predicate_substitution.rs`,
  which enumerates the same leaves from the Rust wire type, substitutes each
  one, and checks the observed decision against the same classification. The
  model also abstracts signature validity and hashing entirely: it starts from
  a statement whose signatures already verify, which is where the reduction to
  EUF-CMA and collision resistance in `docs/papers/evidence-crosses/proof-model.md`
  takes over.
-/

set_option autoImplicit false

namespace Chio.Treaty.AdmissionBinding

/-- What the receiver does with one leaf of the crossing statement. -/
inductive Comparison where
  /-- Compared for equality against the named receiver-held value. -/
  | receiverState (against : String)
  /-- Compared against the named receiver-held value as an inequality, so only
      values outside the admissible interval are refused. -/
  | receiverBound (against : String)
  /-- Constrained to a fixed value or domain the receiver holds as code. A
      constant separates profiles; it does not bind this call. -/
  | shape (domain : String)
  /-- Checked only for agreement with another leaf of the same statement. -/
  | selfConsistent (other : String)
  /-- Not compared at all. -/
  | uncompared (reason : String)
  /-- Required absent from a strict statement. -/
  | absentByProfile (reason : String)
  deriving Repr, DecidableEq, Inhabited

/-- Every leaf a strict bilateral statement can carry. The constructors are in
    wire order, and `path` names each one. -/
inductive Field where
  /-- `_type` -/
  | statementType
  /-- `predicateType` -/
  | predicateTypeField
  /-- `subject/0/name` -/
  | subjectName
  /-- `subject/0/digest/sha256` -/
  | subjectDigest
  /-- `predicate/schema` -/
  | predicateSchema
  /-- `predicate/invocation_id` -/
  | invocationId
  /-- `predicate/tool_server_a/kernel_id` -/
  | originKernelId
  /-- `predicate/tool_server_a/passport_key_fingerprint` -/
  | originFingerprint
  /-- `predicate/tool_server_a/alg` -/
  | originAlg
  /-- `predicate/tool_server_b/kernel_id` -/
  | localKernelId
  /-- `predicate/tool_server_b/passport_key_fingerprint` -/
  | localFingerprint
  /-- `predicate/tool_server_b/alg` -/
  | localAlg
  /-- `predicate/tool_name` -/
  | toolName
  /-- `predicate/co_sign` -/
  | coSign
  /-- `predicate/consistency_model` -/
  | predicateConsistencyModel
  /-- `predicate/cross_org_visibility` -/
  | crossOrgVisibility
  /-- `predicate/timestamp_unix_ms` -/
  | timestampUnixMs
  /-- `predicate/tool_args_hash/alg` -/
  | toolArgsHashAlg
  /-- `predicate/tool_args_hash/value` -/
  | toolArgsHashValue
  /-- `predicate/receipt_canonical_json` -/
  | receiptCanonicalJson
  /-- `predicate/capability_lease_ref/lease_id` -/
  | leaseId
  /-- `predicate/capability_lease_ref/issuer` -/
  | leaseIssuer
  /-- `predicate/capability_lease_ref/expires_at_unix_ms` -/
  | leaseExpiry
  /-- `predicate/capability_lease_ref/scope_digest/alg` -/
  | leaseScopeDigestAlg
  /-- `predicate/capability_lease_ref/scope_digest/value` -/
  | leaseScopeDigestValue
  /-- `predicate/policy_evaluation_summary/server_a_verdict/verdict` -/
  | originVerdict
  /-- `predicate/policy_evaluation_summary/server_a_verdict/policy_id` -/
  | originPolicyId
  /-- `predicate/policy_evaluation_summary/server_a_verdict/policy_version` -/
  | originPolicyVersion
  /-- `predicate/policy_evaluation_summary/server_a_verdict/rationale_code` -/
  | originRationaleCode
  /-- `predicate/policy_evaluation_summary/server_b_verdict/verdict` -/
  | localVerdict
  /-- `predicate/policy_evaluation_summary/server_b_verdict/policy_id` -/
  | localPolicyId
  /-- `predicate/policy_evaluation_summary/server_b_verdict/policy_version` -/
  | localPolicyVersion
  /-- `predicate/policy_evaluation_summary/server_b_verdict/rationale_code` -/
  | localRationaleCode
  /-- `predicate/policy_evaluation_summary/joint_disposition` -/
  | jointDisposition
  /-- `predicate/governance_receipt_ref/receipt_id` -/
  | governanceReceiptId
  /-- `predicate/governance_receipt_ref/kernel_id` -/
  | governanceKernelId
  /-- `predicate/governance_receipt_ref/digest/alg` -/
  | governanceDigestAlg
  /-- `predicate/governance_receipt_ref/digest/value` -/
  | governanceDigestValue
  /-- `predicate/consistency_anchor` -/
  | consistencyAnchor
  /-- `predicate/treaty_binding_ref/treaty_id` -/
  | treatyId
  /-- `predicate/treaty_binding_ref/treaty_scope_sha256` -/
  | treatyScopeDigest
  /-- `predicate/treaty_binding_ref/ladder_intersection_sha256` -/
  | ladderIntersectionDigest
  /-- `predicate/treaty_binding_ref/admission_report_sha256` -/
  | admissionReportDigest
  /-- `predicate/treaty_binding_ref/continuation_sha256` -/
  | continuationDigest
  /-- `predicate/treaty_binding_ref/lineage_bundle_sha256` -/
  | lineageBundleDigest
  /-- `predicate/treaty_binding_ref/action_class_id` -/
  | actionClassId
  /-- `predicate/treaty_binding_ref/consistency_model` -/
  | bindingConsistencyModel
  /-- `predicate/treaty_binding_ref/request_sha256` -/
  | requestDigest
  /-- `predicate/treaty_binding_ref/outcome_sha256` -/
  | outcomeDigest
  /-- `predicate/treaty_binding_ref/local_receipt_sha256` -/
  | localReceiptDigest
  /-- `predicate/treaty_binding_ref/remote_receipt_sha256` -/
  | remoteReceiptDigest
  /-- `predicate/treaty_binding_ref/lease_refs/0` -/
  | leaseRef
  /-- `predicate/treaty_binding_ref/governance_refs/0` -/
  | governanceRef
  /-- `predicate/treaty_binding_ref/signer_kernel_ids/0` -/
  | originSignerId
  /-- `predicate/treaty_binding_ref/signer_kernel_ids/1` -/
  | localSignerId
  deriving Repr, DecidableEq, Inhabited

/-- The wire path of each leaf, as the substitution corpus addresses it. -/
def path : Field -> String := fun f =>
  match f with
  | .statementType => "_type"
  | .predicateTypeField => "predicateType"
  | .subjectName => "subject/0/name"
  | .subjectDigest => "subject/0/digest/sha256"
  | .predicateSchema => "predicate/schema"
  | .invocationId => "predicate/invocation_id"
  | .originKernelId => "predicate/tool_server_a/kernel_id"
  | .originFingerprint => "predicate/tool_server_a/passport_key_fingerprint"
  | .originAlg => "predicate/tool_server_a/alg"
  | .localKernelId => "predicate/tool_server_b/kernel_id"
  | .localFingerprint => "predicate/tool_server_b/passport_key_fingerprint"
  | .localAlg => "predicate/tool_server_b/alg"
  | .toolName => "predicate/tool_name"
  | .coSign => "predicate/co_sign"
  | .predicateConsistencyModel => "predicate/consistency_model"
  | .crossOrgVisibility => "predicate/cross_org_visibility"
  | .timestampUnixMs => "predicate/timestamp_unix_ms"
  | .toolArgsHashAlg => "predicate/tool_args_hash/alg"
  | .toolArgsHashValue => "predicate/tool_args_hash/value"
  | .receiptCanonicalJson => "predicate/receipt_canonical_json"
  | .leaseId => "predicate/capability_lease_ref/lease_id"
  | .leaseIssuer => "predicate/capability_lease_ref/issuer"
  | .leaseExpiry => "predicate/capability_lease_ref/expires_at_unix_ms"
  | .leaseScopeDigestAlg => "predicate/capability_lease_ref/scope_digest/alg"
  | .leaseScopeDigestValue => "predicate/capability_lease_ref/scope_digest/value"
  | .originVerdict => "predicate/policy_evaluation_summary/server_a_verdict/verdict"
  | .originPolicyId => "predicate/policy_evaluation_summary/server_a_verdict/policy_id"
  | .originPolicyVersion => "predicate/policy_evaluation_summary/server_a_verdict/policy_version"
  | .originRationaleCode => "predicate/policy_evaluation_summary/server_a_verdict/rationale_code"
  | .localVerdict => "predicate/policy_evaluation_summary/server_b_verdict/verdict"
  | .localPolicyId => "predicate/policy_evaluation_summary/server_b_verdict/policy_id"
  | .localPolicyVersion => "predicate/policy_evaluation_summary/server_b_verdict/policy_version"
  | .localRationaleCode => "predicate/policy_evaluation_summary/server_b_verdict/rationale_code"
  | .jointDisposition => "predicate/policy_evaluation_summary/joint_disposition"
  | .governanceReceiptId => "predicate/governance_receipt_ref/receipt_id"
  | .governanceKernelId => "predicate/governance_receipt_ref/kernel_id"
  | .governanceDigestAlg => "predicate/governance_receipt_ref/digest/alg"
  | .governanceDigestValue => "predicate/governance_receipt_ref/digest/value"
  | .consistencyAnchor => "predicate/consistency_anchor"
  | .treatyId => "predicate/treaty_binding_ref/treaty_id"
  | .treatyScopeDigest => "predicate/treaty_binding_ref/treaty_scope_sha256"
  | .ladderIntersectionDigest => "predicate/treaty_binding_ref/ladder_intersection_sha256"
  | .admissionReportDigest => "predicate/treaty_binding_ref/admission_report_sha256"
  | .continuationDigest => "predicate/treaty_binding_ref/continuation_sha256"
  | .lineageBundleDigest => "predicate/treaty_binding_ref/lineage_bundle_sha256"
  | .actionClassId => "predicate/treaty_binding_ref/action_class_id"
  | .bindingConsistencyModel => "predicate/treaty_binding_ref/consistency_model"
  | .requestDigest => "predicate/treaty_binding_ref/request_sha256"
  | .outcomeDigest => "predicate/treaty_binding_ref/outcome_sha256"
  | .localReceiptDigest => "predicate/treaty_binding_ref/local_receipt_sha256"
  | .remoteReceiptDigest => "predicate/treaty_binding_ref/remote_receipt_sha256"
  | .leaseRef => "predicate/treaty_binding_ref/lease_refs/0"
  | .governanceRef => "predicate/treaty_binding_ref/governance_refs/0"
  | .originSignerId => "predicate/treaty_binding_ref/signer_kernel_ids/0"
  | .localSignerId => "predicate/treaty_binding_ref/signer_kernel_ids/1"

/-- The classification of each leaf. This match is the totality argument: a
    leaf added to `Field` does not elaborate until it is classified here. -/
def classify : Field -> Comparison := fun f =>
  match f with
  | .statementType =>
      .shape "the in-toto Statement v1 type constant"
  | .predicateTypeField =>
      .shape "the strict bilateral-cosign-invocation predicate type constant"
  | .subjectName =>
      .selfConsistent "the receipt subject name derived from predicate.invocation_id"
  | .subjectDigest =>
      .uncompared "the receipts are bound through the binding reference, not through the subject digest"
  | .predicateSchema =>
      .absentByProfile "a strict predicate carries no schema discriminator"
  | .invocationId =>
      .selfConsistent "the subject name, which must be its receipt-subject form"
  | .originKernelId =>
      .receiverState "the origin kernel id of the request"
  | .originFingerprint =>
      .receiverState "the key id of the pinned public key of the origin signer"
  | .originAlg =>
      .shape "the ed25519 algorithm constant"
  | .localKernelId =>
      .receiverState "the receiving kernel's own id"
  | .localFingerprint =>
      .receiverState "the key id of the pinned public key of the receiving signer"
  | .localAlg =>
      .shape "the ed25519 algorithm constant"
  | .toolName =>
      .receiverState "the tool name of the request being admitted"
  | .coSign =>
      .receiverState "the co-signing mode of the resolved action class"
  | .predicateConsistencyModel =>
      .receiverState "the consistency model of the resolved action class"
  | .crossOrgVisibility =>
      .shape "the four declared visibility labels, and nothing else"
  | .timestampUnixMs =>
      .uncompared "the presentation window comes from the continuation, the lease, and the agreement"
  | .toolArgsHashAlg =>
      .shape "the sha256 algorithm constant"
  | .toolArgsHashValue =>
      .receiverState "the canonical argument hash of the request"
  | .receiptCanonicalJson =>
      .absentByProfile "the embedded receipt copy belongs to the compatibility profile"
  | .leaseId =>
      .selfConsistent "the lease list of the binding reference"
  | .leaseIssuer =>
      .receiverState "the participant kernel ids of the resolved agreement"
  | .leaseExpiry =>
      .receiverBound "the receiver's clock, as a strict lower bound"
  | .leaseScopeDigestAlg =>
      .absentByProfile "the optional lease scope digest is not carried by this call"
  | .leaseScopeDigestValue =>
      .absentByProfile "the optional lease scope digest is not carried by this call"
  | .originVerdict =>
      .selfConsistent "the peer verdict and the joint disposition, and required to be allow"
  | .originPolicyId =>
      .uncompared "the receiver resolves neither party's policy identity"
  | .originPolicyVersion =>
      .uncompared "the receiver resolves neither party's policy version"
  | .originRationaleCode =>
      .absentByProfile "the optional rationale code is not carried by this call"
  | .localVerdict =>
      .selfConsistent "the peer verdict and the joint disposition"
  | .localPolicyId =>
      .uncompared "the receiver resolves neither party's policy identity"
  | .localPolicyVersion =>
      .uncompared "the receiver resolves neither party's policy version"
  | .localRationaleCode =>
      .absentByProfile "the optional rationale code is not carried by this call"
  | .jointDisposition =>
      .selfConsistent "the two verdicts it summarizes"
  | .governanceReceiptId =>
      .selfConsistent "the governance list of the binding reference"
  | .governanceKernelId =>
      .uncompared "the governance receipt the receiver acts on is the one its own bundle names"
  | .governanceDigestAlg =>
      .uncompared "the governance digest is never resolved during admission"
  | .governanceDigestValue =>
      .uncompared "the governance digest is never resolved during admission"
  | .consistencyAnchor =>
      .uncompared "the anchor is carried for the peer's own reconciliation"
  | .treatyId =>
      .receiverState "the identifier of the agreement the receiver resolved"
  | .treatyScopeDigest =>
      .receiverState "the digest the receiver recomputes over its own agreement"
  | .ladderIntersectionDigest =>
      .receiverState "the digest of the intersection the receiver resolved"
  | .admissionReportDigest =>
      .uncompared "overwritten with the digest of the receiver's own report before signing"
  | .continuationDigest =>
      .receiverState "the digest of the continuation the receiver resolved"
  | .lineageBundleDigest =>
      .receiverState "the digest of the lineage bundle the receiver resolved"
  | .actionClassId =>
      .receiverState "the action class the receiver resolved for this request"
  | .bindingConsistencyModel =>
      .receiverState "the consistency model of the resolved action class"
  | .requestDigest =>
      .receiverState "the canonical argument hash in the receiver's admission bundle"
  | .outcomeDigest =>
      .receiverState "the outcome digest of the resolved invocation record"
  | .localReceiptDigest =>
      .receiverState "the root receipt digest of the resolved lineage bundle and record"
  | .remoteReceiptDigest =>
      .receiverState "the leaf receipt digest of the resolved lineage bundle and record"
  | .leaseRef =>
      .receiverState "the lease id in the receiver's own admission bundle"
  | .governanceRef =>
      .receiverState "the governance receipt id in the receiver's own admission bundle"
  | .originSignerId =>
      .receiverState "the participant set of the resolved agreement"
  | .localSignerId =>
      .receiverState "the participant set of the resolved agreement"

/-- The enumeration as a list, for the statements that quantify over it. -/
def allFields : List Field :=
  [.statementType,
   .predicateTypeField,
   .subjectName,
   .subjectDigest,
   .predicateSchema,
   .invocationId,
   .originKernelId,
   .originFingerprint,
   .originAlg,
   .localKernelId,
   .localFingerprint,
   .localAlg,
   .toolName,
   .coSign,
   .predicateConsistencyModel,
   .crossOrgVisibility,
   .timestampUnixMs,
   .toolArgsHashAlg,
   .toolArgsHashValue,
   .receiptCanonicalJson,
   .leaseId,
   .leaseIssuer,
   .leaseExpiry,
   .leaseScopeDigestAlg,
   .leaseScopeDigestValue,
   .originVerdict,
   .originPolicyId,
   .originPolicyVersion,
   .originRationaleCode,
   .localVerdict,
   .localPolicyId,
   .localPolicyVersion,
   .localRationaleCode,
   .jointDisposition,
   .governanceReceiptId,
   .governanceKernelId,
   .governanceDigestAlg,
   .governanceDigestValue,
   .consistencyAnchor,
   .treatyId,
   .treatyScopeDigest,
   .ladderIntersectionDigest,
   .admissionReportDigest,
   .continuationDigest,
   .lineageBundleDigest,
   .actionClassId,
   .bindingConsistencyModel,
   .requestDigest,
   .outcomeDigest,
   .localReceiptDigest,
   .remoteReceiptDigest,
   .leaseRef,
   .governanceRef,
   .originSignerId,
   .localSignerId]

/-- The receiver-held value a leaf is compared against, when there is one. -/
def comparedAgainst : Comparison -> Option String := fun c =>
  match c with
  | .receiverState against => some against
  | .receiverBound against => some against
  | .shape _ => none
  | .selfConsistent _ => none
  | .uncompared _ => none
  | .absentByProfile _ => none

/-- A leaf constrained only against the statement itself, never against
    anything the receiver holds. -/
def statementOnly : Comparison -> Bool := fun c =>
  match c with
  | .receiverState _ => false
  | .receiverBound _ => false
  | .shape _ => true
  | .selfConsistent _ => true
  | .uncompared _ => false
  | .absentByProfile _ => false

/-- A leaf nothing constrains. -/
def unconstrained : Comparison -> Bool := fun c =>
  match c with
  | .receiverState _ => false
  | .receiverBound _ => false
  | .shape _ => false
  | .selfConsistent _ => false
  | .uncompared _ => true
  | .absentByProfile _ => true

/-- A statement, as the values it carries at each leaf. -/
abbrev Statement := Field -> String

/-- The receiver's own state, as the value each named receiver-side quantity
    holds for this call. -/
abbrev ReceiverState := String -> String

/-- The comparison one leaf contributes to the receiver's decision. A leaf the
    classification does not bind to receiver state contributes nothing, which
    is what makes the accept predicate below exactly the comparison set. -/
def fieldAgrees (st : Statement) (rs : ReceiverState) (f : Field) : Bool :=
  match comparedAgainst (classify f) with
  | some against => decide (st f = rs against)
  | none => true

/-- The receiver's accept predicate: the conjunction of the comparisons the
    classification names, over the whole enumeration. -/
def accept (st : Statement) (rs : ReceiverState) : Bool :=
  allFields.all (fieldAgrees st rs)

/-- The enumeration covers the type. -/
theorem mem_allFields (f : Field) : f ∈ allFields := by
  cases f <;> decide

/-- The enumeration lists each leaf once. -/
theorem allFields_nodup : allFields.Nodup := by
  decide

/-- The statement carries exactly fifty-five leaves. -/
theorem allFields_length : allFields.length = 55 := by
  rfl

/--
  Classification trichotomy: every leaf is bound to a named receiver-held
  value, or constrained only against the statement itself, or constrained by
  nothing, and never more than one of the three. This is the completeness
  claim the substitution corpus discharges case by case: there is no fourth
  possibility and no unclassified leaf.
-/
theorem classification_trichotomy (f : Field) :
    (((comparedAgainst (classify f)).isSome = true) ∧
       statementOnly (classify f) = false ∧ unconstrained (classify f) = false) ∨
    (((comparedAgainst (classify f)).isSome = false) ∧
       statementOnly (classify f) = true ∧ unconstrained (classify f) = false) ∨
    (((comparedAgainst (classify f)).isSome = false) ∧
       statementOnly (classify f) = false ∧ unconstrained (classify f) = true) := by
  cases f <;> decide

/--
  Accept-set decomposition: the receiver accepts exactly when every leaf bound
  to a receiver-held value carries that value. The bi-conditional is the
  load-bearing direction: nothing outside the comparison set can deny, and
  nothing outside it can admit.
-/
theorem accept_iff_bound_fields_agree (st : Statement) (rs : ReceiverState) :
    accept st rs = true ↔
      ∀ f : Field, ∀ against : String,
        comparedAgainst (classify f) = some against -> st f = rs against := by
  constructor
  · intro hAccept f against hBound
    have hField : fieldAgrees st rs f = true :=
      List.all_eq_true.mp hAccept f (mem_allFields f)
    simp [fieldAgrees, hBound] at hField
    exact hField
  · intro hAgree
    refine List.all_eq_true.mpr ?_
    intro f _
    unfold fieldAgrees
    cases hBound : comparedAgainst (classify f) with
    | none => rfl
    | some against => simp [hAgree f against hBound]

/--
  Admission binding, field by field: an accepted statement carries, at every
  leaf the classification binds, the value the receiver already held.
-/
theorem accept_implies_binding
    (st : Statement) (rs : ReceiverState) (f : Field) (against : String)
    (hBound : comparedAgainst (classify f) = some against)
    (hAccept : accept st rs = true) :
    st f = rs against :=
  (accept_iff_bound_fields_agree st rs).mp hAccept f against hBound

/--
  Fail-closed contrapositive: one bound leaf that disagrees with the value the
  receiver holds is enough to deny, whatever the rest of the statement says.
-/
theorem disagreement_denies
    (st : Statement) (rs : ReceiverState) (f : Field) (against : String)
    (hBound : comparedAgainst (classify f) = some against)
    (hDiffers : st f ≠ rs against) :
    accept st rs = false := by
  cases hAccept : accept st rs with
  | false => rfl
  | true => exact absurd (accept_implies_binding st rs f against hBound hAccept) hDiffers

/--
  Acceptance is a function of the bound leaves alone: two statements that agree
  on every leaf the classification binds are accepted or refused together. This
  is the completeness statement in its strongest form, and its converse reading
  is the residual: the leaves it does not mention are free.
-/
theorem accept_determined_by_bound_fields
    (st st' : Statement) (rs : ReceiverState)
    (hAgree : ∀ f : Field, ∀ against : String,
      comparedAgainst (classify f) = some against -> st f = st' f) :
    accept st rs = accept st' rs := by
  have hPointwise : fieldAgrees st rs = fieldAgrees st' rs := by
    funext f
    unfold fieldAgrees
    cases hBound : comparedAgainst (classify f) with
    | none => rfl
    | some against => rw [hAgree f against hBound]
  unfold accept
  rw [hPointwise]

/--
  The residual, stated directly: substituting any leaf the classification does
  not bind to receiver state leaves the decision unchanged. An adversary who
  can produce both signatures chooses these freely, and the receiver admits.
-/
theorem unbound_substitution_preserves_acceptance
    (st : Statement) (rs : ReceiverState) (g : Field) (replacement : String)
    (hUnbound : comparedAgainst (classify g) = none) :
    accept (fun f => if f = g then replacement else st f) rs = accept st rs := by
  refine accept_determined_by_bound_fields _ _ rs ?_
  intro f against hBound
  have hne : f ≠ g := by
    intro hEq
    rw [hEq, hUnbound] at hBound
    simp at hBound
  simp [hne]

end Chio.Treaty.AdmissionBinding
