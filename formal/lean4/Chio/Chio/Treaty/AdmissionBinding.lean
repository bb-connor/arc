/-
  Comparison-set completeness for cross-organization admission.

  The receiver of a co-signed bilateral statement decides a call by comparing
  fields of that statement against values it already holds. This module makes
  the set of those comparisons a closed object: `Field` enumerates every leaf
  the wire type can carry, `classify` assigns each leaf exactly one
  classification, and `accept` is the statement gate followed by the
  conjunction of the comparisons the classification names. Totality is
  structural rather than asserted, because `classify` is a match on `Field`: a
  leaf added to the statement adds a constructor, and the match does not
  elaborate until the new leaf is classified.

  Three things the model keeps apart, because the receiver keeps them apart.

  * A leaf bound for **equality** must carry the value the receiver already
    holds. Twenty-three leaves are of this kind.
  * A leaf bound to a **domain** must lie in an admissible set the receiver
    holds, which is not a singleton: the lease expiry must be later than the
    receiver's clock, and the lease issuer must be one of the agreement's two
    participants. Two leaves are of this kind, and an accepted statement pins
    them to the set rather than to a value.
  * The **statement gate** is everything the receiver checks about the
    statement alone: the wire shape of each leaf, and the agreement checks
    between leaves of the same statement. It reads nothing the receiver holds,
    and it is what a substitution outside a leaf's declared shape trips.

  What the theorems below establish, over this model:

  * every leaf a strict statement of this call carries falls into exactly one
    of three kinds: compared against something the receiver holds, constrained
    only against the statement itself or against a constant, or compared
    against nothing the receiver holds;
  * the leaves this call does not carry are of two kinds, and only one of them
    is a property of the strict profile: two leaves the profile refuses
    outright, and four the wire type marks optional and this call omits, which
    another statement may carry;
  * acceptance holds exactly when the statement gate holds and every
    equality-bound leaf carries its receiver-held value and every domain-bound
    leaf lies in its receiver-held set, so no further gate and no hidden gate
    can carry it;
  * acceptance therefore implies the binding claim leaf by leaf, and a single
    disagreeing equality-bound leaf or a single domain-bound leaf outside its
    set denies;
  * acceptance is a function of the statement gate and the compared leaves
    alone, so the residual an adversary who can produce both signatures may
    choose is exactly the leaves no comparison names, bounded by what the
    statement gate still accepts.

  What they do not establish. The classification is a model of the receiver's
  checks, not an extraction of them: nothing here proves that the shipped
  admission hook realizes this table. That link is carried by the executed
  substitution corpus in
  `crates/kernel/chio-runtime-core/tests/runtime_treaty_predicate_substitution.rs`,
  which enumerates the same leaves from the Rust wire type, substitutes each
  one, and checks the observed decision against the same classification; that
  corpus also reads this file and asserts that the two enumerations and the two
  classifications agree leaf for leaf, so the transcription cannot drift
  silently. The model abstracts signature validity and hashing entirely: it
  starts from a statement whose signatures already verify, which is where the
  reduction to EUF-CMA and collision resistance in
  `docs/papers/evidence-crosses/proof-model.md` takes over. It also keeps the
  statement gate opaque: the model says a residual substitution is invisible
  exactly when the gate's verdict does not move, and says nothing about which
  values move it.
-/

set_option autoImplicit false

namespace Chio.Treaty.AdmissionBinding

/-- What the receiver does with one leaf of the crossing statement. -/
inductive Comparison where
  /-- Compared for equality against the named receiver-held value. -/
  | receiverState (against : String)
  /-- Required to lie in the admissible set the receiver holds under this name.
      The set is not a singleton, so an accepted statement pins the leaf to the
      set and not to a value. -/
  | receiverDomain (against : String)
  /-- Constrained to a fixed value or domain the receiver holds as code. A
      constant separates profiles; it does not bind this call. -/
  | shape (domain : String)
  /-- Checked only for agreement with another leaf of the same statement. -/
  | selfConsistent (other : String)
  /-- Compared against nothing the receiver holds. `shape` records what the
      wire form still requires of the value, which is the domain an adversary
      chooses inside; `reason` says why admission reads nothing else from it. -/
  | uncompared (shape : String) (reason : String)
  /-- Refused outright by the strict profile: a statement carrying it is
      rejected before any comparison runs. -/
  | absentRequired (reason : String)
  /-- Marked optional by the wire type and not carried by this call. The strict
      profile does not refuse it, so another statement may carry it. -/
  | absentOptional (reason : String)
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
      .uncompared "any JSON string"
        "the receipts are bound through the binding reference, not through the subject digest"
  | .predicateSchema =>
      .absentRequired "a strict predicate carries no schema discriminator"
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
      .uncompared "any unsigned integer"
        "the presentation window comes from the continuation, the lease, and the agreement"
  | .toolArgsHashAlg =>
      .shape "the sha256 algorithm constant"
  | .toolArgsHashValue =>
      .receiverState "the canonical argument hash of the request"
  | .receiptCanonicalJson =>
      .absentRequired "the embedded receipt copy belongs to the compatibility profile"
  | .leaseId =>
      .selfConsistent "the lease list of the binding reference"
  | .leaseIssuer =>
      .receiverDomain "the two participant kernel ids of the resolved agreement"
  | .leaseExpiry =>
      .receiverDomain "the instants strictly later than the receiver's clock"
  | .leaseScopeDigestAlg =>
      .absentOptional "the lease scope digest is optional and this call omits it"
  | .leaseScopeDigestValue =>
      .absentOptional "the lease scope digest is optional and this call omits it"
  | .originVerdict =>
      .selfConsistent "the peer verdict and the joint disposition, and required to be allow"
  | .originPolicyId =>
      .uncompared "any non-empty JSON string"
        "the receiver resolves neither party's policy identity"
  | .originPolicyVersion =>
      .uncompared "any non-empty JSON string"
        "the receiver resolves neither party's policy version"
  | .originRationaleCode =>
      .absentOptional "the rationale code is optional and this call omits it"
  | .localVerdict =>
      .selfConsistent "the peer verdict and the joint disposition"
  | .localPolicyId =>
      .uncompared "any non-empty JSON string"
        "the receiver resolves neither party's policy identity"
  | .localPolicyVersion =>
      .uncompared "any non-empty JSON string"
        "the receiver resolves neither party's policy version"
  | .localRationaleCode =>
      .absentOptional "the rationale code is optional and this call omits it"
  | .jointDisposition =>
      .selfConsistent "the two verdicts it summarizes"
  | .governanceReceiptId =>
      .selfConsistent "the governance list of the binding reference"
  | .governanceKernelId =>
      .uncompared "any JSON string"
        "the governance receipt the receiver acts on is the one its own bundle names"
  | .governanceDigestAlg =>
      .uncompared "any JSON string"
        "the governance digest is never resolved during admission"
  | .governanceDigestValue =>
      .uncompared "any JSON string"
        "the governance digest is never resolved during admission"
  | .consistencyAnchor =>
      .uncompared "any JSON string"
        "the anchor is carried for the peer's own reconciliation"
  | .treatyId =>
      .receiverState "the identifier of the agreement the receiver resolved"
  | .treatyScopeDigest =>
      .receiverState "the digest the receiver recomputes over its own agreement"
  | .ladderIntersectionDigest =>
      .receiverState "the digest of the intersection the receiver resolved"
  | .admissionReportDigest =>
      .uncompared "sixty-four lowercase hex characters"
        "overwritten with the digest of the receiver's own report before signing"
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

/-- The receiver-held value a leaf must equal, when the classification binds it
    to one. -/
def comparedForEquality : Comparison -> Option String := fun c =>
  match c with
  | .receiverState against => some against
  | .receiverDomain _ => none
  | .shape _ => none
  | .selfConsistent _ => none
  | .uncompared _ _ => none
  | .absentRequired _ => none
  | .absentOptional _ => none

/-- The receiver-held admissible set a leaf must lie in, when the
    classification binds it to one. -/
def comparedWithinDomain : Comparison -> Option String := fun c =>
  match c with
  | .receiverState _ => none
  | .receiverDomain against => some against
  | .shape _ => none
  | .selfConsistent _ => none
  | .uncompared _ _ => none
  | .absentRequired _ => none
  | .absentOptional _ => none

/-- A leaf the receiver compares against something it holds, either for
    equality or for membership in a domain. -/
def comparedAgainstReceiver : Comparison -> Bool := fun c =>
  (comparedForEquality c).isSome || (comparedWithinDomain c).isSome

/-- A leaf constrained only against the statement itself, never against
    anything the receiver holds. -/
def statementOnly : Comparison -> Bool := fun c =>
  match c with
  | .receiverState _ => false
  | .receiverDomain _ => false
  | .shape _ => true
  | .selfConsistent _ => true
  | .uncompared _ _ => false
  | .absentRequired _ => false
  | .absentOptional _ => false

/-- A leaf no receiver-held value constrains. Its declared wire shape may still
    constrain it, which is what the `uncompared` payload records: this is the
    residual, not an unconstrained field. -/
def receiverUncompared : Comparison -> Bool := fun c =>
  match c with
  | .receiverState _ => false
  | .receiverDomain _ => false
  | .shape _ => false
  | .selfConsistent _ => false
  | .uncompared _ _ => true
  | .absentRequired _ => false
  | .absentOptional _ => false

/-- A leaf this call's statement carries. -/
def carried : Comparison -> Bool := fun c =>
  match c with
  | .receiverState _ => true
  | .receiverDomain _ => true
  | .shape _ => true
  | .selfConsistent _ => true
  | .uncompared _ _ => true
  | .absentRequired _ => false
  | .absentOptional _ => false

/-- A leaf the strict profile refuses outright, so no strict statement carries
    it. -/
def refusedByProfile : Comparison -> Bool := fun c =>
  match c with
  | .receiverState _ => false
  | .receiverDomain _ => false
  | .shape _ => false
  | .selfConsistent _ => false
  | .uncompared _ _ => false
  | .absentRequired _ => true
  | .absentOptional _ => false

/-- A leaf the wire type marks optional and this call omits. Another strict
    statement may carry it, so its absence here is a property of the call and
    not of the profile. -/
def optionalAndAbsent : Comparison -> Bool := fun c =>
  match c with
  | .receiverState _ => false
  | .receiverDomain _ => false
  | .shape _ => false
  | .selfConsistent _ => false
  | .uncompared _ _ => false
  | .absentRequired _ => false
  | .absentOptional _ => true

/-- A statement, as the values it carries at each leaf. -/
abbrev Statement := Field -> String

/-- What the receiver brings to the decision.

    `value` is the quantity an equality-bound leaf is compared against.
    `admits` decides the admissible set a domain-bound leaf must lie in.
    `statementGate` is everything the receiver checks about the statement
    alone: the wire shape of each leaf, and the agreement checks between leaves
    of the same statement. The gate reads nothing the receiver holds, which is
    why it is one opaque function here rather than a second classification. -/
structure ReceiverState where
  value : String -> String
  admits : String -> String -> Bool
  statementGate : Statement -> Bool

/-- The comparison one leaf contributes to the receiver's decision. A leaf the
    classification binds to neither a receiver-held value nor a receiver-held
    domain contributes nothing here; what constrains it is the statement
    gate. -/
def fieldAgrees (st : Statement) (rs : ReceiverState) (f : Field) : Bool :=
  (match comparedForEquality (classify f) with
   | some against => decide (st f = rs.value against)
   | none => true)
  &&
  (match comparedWithinDomain (classify f) with
   | some against => rs.admits against (st f)
   | none => true)

/-- The receiver's accept predicate: the statement gate, and then the
    conjunction of the comparisons the classification names. -/
def accept (st : Statement) (rs : ReceiverState) : Bool :=
  rs.statementGate st && allFields.all (fieldAgrees st rs)

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
  Classification trichotomy over the leaves this call's statement carries:
  every such leaf is compared against something the receiver holds, or
  constrained only against the statement itself, or compared against nothing
  the receiver holds, and never more than one of the three. This is the
  completeness claim the substitution corpus discharges case by case: there is
  no fourth possibility and no unclassified leaf. The third branch is the
  residual, and it says the receiver compares the leaf against nothing, not
  that nothing constrains it: the statement gate still enforces the leaf's
  declared shape.
-/
theorem classification_trichotomy (f : Field) :
    carried (classify f) = true ->
    ((comparedAgainstReceiver (classify f) = true ∧
        statementOnly (classify f) = false ∧ receiverUncompared (classify f) = false) ∨
     (comparedAgainstReceiver (classify f) = false ∧
        statementOnly (classify f) = true ∧ receiverUncompared (classify f) = false) ∨
     (comparedAgainstReceiver (classify f) = false ∧
        statementOnly (classify f) = false ∧ receiverUncompared (classify f) = true)) := by
  cases f <;> decide

/--
  The leaves this call's statement does not carry are of two kinds, and only
  one of them is a property of the strict profile. A refused leaf is rejected
  outright; an optional leaf is one the wire type permits and this call omits,
  so another strict statement may carry it and the substitution corpus cannot
  reach it by substitution.
-/
theorem absent_leaves_are_refused_or_merely_optional (f : Field) :
    carried (classify f) = false ->
    ((refusedByProfile (classify f) = true ∧ optionalAndAbsent (classify f) = false) ∨
     (refusedByProfile (classify f) = false ∧ optionalAndAbsent (classify f) = true)) := by
  cases f <;> decide

/--
  The census of the classification, which is what the counts in the companion
  document must agree with: twenty-three leaves compared for equality, two
  compared against a receiver-held domain, thirteen constrained only against
  the statement, eleven compared against nothing the receiver holds, two
  refused by the strict profile, four optional and omitted by this call,
  forty-nine carried by this call, and fifty-three that a strict statement may
  carry.
-/
theorem classification_census :
    (allFields.filter (fun f => (comparedForEquality (classify f)).isSome)).length = 23 ∧
    (allFields.filter (fun f => (comparedWithinDomain (classify f)).isSome)).length = 2 ∧
    (allFields.filter (fun f => statementOnly (classify f))).length = 13 ∧
    (allFields.filter (fun f => receiverUncompared (classify f))).length = 11 ∧
    (allFields.filter (fun f => refusedByProfile (classify f))).length = 2 ∧
    (allFields.filter (fun f => optionalAndAbsent (classify f))).length = 4 ∧
    (allFields.filter (fun f => carried (classify f))).length = 49 ∧
    (allFields.filter (fun f => !refusedByProfile (classify f))).length = 53 := by
  decide

/--
  Accept-set decomposition: the receiver accepts exactly when the statement
  gate holds, every leaf bound to a receiver-held value carries that value, and
  every leaf bound to a receiver-held domain lies in it. The forward direction
  is what the binding claim rests on; the converse is what says the comparison
  set is the whole of the receiver-state half of the decision, with the gate
  named explicitly rather than absorbed into it.
-/
theorem accept_iff_gate_and_comparisons_hold (st : Statement) (rs : ReceiverState) :
    accept st rs = true ↔
      (rs.statementGate st = true ∧
       (∀ f : Field, ∀ against : String,
          comparedForEquality (classify f) = some against -> st f = rs.value against) ∧
       (∀ f : Field, ∀ against : String,
          comparedWithinDomain (classify f) = some against ->
            rs.admits against (st f) = true)) := by
  constructor
  · intro hAccept
    rw [accept, Bool.and_eq_true] at hAccept
    obtain ⟨hGate, hAll⟩ := hAccept
    refine ⟨hGate, ?_, ?_⟩
    · intro f against hEqBound
      have hField : fieldAgrees st rs f = true :=
        List.all_eq_true.mp hAll f (mem_allFields f)
      rw [fieldAgrees, Bool.and_eq_true] at hField
      have hLeft := hField.1
      rw [hEqBound] at hLeft
      simpa using hLeft
    · intro f against hDomainBound
      have hField : fieldAgrees st rs f = true :=
        List.all_eq_true.mp hAll f (mem_allFields f)
      rw [fieldAgrees, Bool.and_eq_true] at hField
      have hRight := hField.2
      rw [hDomainBound] at hRight
      simpa using hRight
  · rintro ⟨hGate, hEq, hDomain⟩
    rw [accept, Bool.and_eq_true]
    refine ⟨hGate, List.all_eq_true.mpr ?_⟩
    intro f _
    rw [fieldAgrees, Bool.and_eq_true]
    constructor
    · cases hEqBound : comparedForEquality (classify f) with
      | none => rfl
      | some against => simpa using hEq f against hEqBound
    · cases hDomainBound : comparedWithinDomain (classify f) with
      | none => rfl
      | some against => simpa using hDomain f against hDomainBound

/--
  Admission binding, leaf by leaf: an accepted statement carries, at every leaf
  the classification binds for equality, the value the receiver already held.
-/
theorem accept_implies_binding
    (st : Statement) (rs : ReceiverState) (f : Field) (against : String)
    (hBound : comparedForEquality (classify f) = some against)
    (hAccept : accept st rs = true) :
    st f = rs.value against :=
  ((accept_iff_gate_and_comparisons_hold st rs).mp hAccept).2.1 f against hBound

/--
  The weaker half of the binding claim, stated separately because it is weaker:
  at a leaf the classification binds to a receiver-held domain, an accepted
  statement carries a value inside that domain and nothing more. The lease
  expiry and the lease issuer are of this kind, and no accepted statement pins
  either to a receiver-held value.
-/
theorem accept_implies_domain_membership
    (st : Statement) (rs : ReceiverState) (f : Field) (against : String)
    (hBound : comparedWithinDomain (classify f) = some against)
    (hAccept : accept st rs = true) :
    rs.admits against (st f) = true :=
  ((accept_iff_gate_and_comparisons_hold st rs).mp hAccept).2.2 f against hBound

/--
  Fail-closed contrapositive: one equality-bound leaf that disagrees with the
  value the receiver holds is enough to deny, whatever the rest of the
  statement says.
-/
theorem disagreement_denies
    (st : Statement) (rs : ReceiverState) (f : Field) (against : String)
    (hBound : comparedForEquality (classify f) = some against)
    (hDiffers : st f ≠ rs.value against) :
    accept st rs = false := by
  cases hAccept : accept st rs with
  | false => rfl
  | true => exact absurd (accept_implies_binding st rs f against hBound hAccept) hDiffers

/--
  Fail-closed contrapositive for the domain-bound leaves: a value outside the
  receiver-held set denies, which is the form the lease expiry and the lease
  issuer take.
-/
theorem value_outside_domain_denies
    (st : Statement) (rs : ReceiverState) (f : Field) (against : String)
    (hBound : comparedWithinDomain (classify f) = some against)
    (hOutside : rs.admits against (st f) = false) :
    accept st rs = false := by
  cases hAccept : accept st rs with
  | false => rfl
  | true =>
    have hInside := accept_implies_domain_membership st rs f against hBound hAccept
    simp [hInside] at hOutside

/--
  Acceptance is a function of the statement gate and the compared leaves alone:
  two statements the gate treats alike, and which agree on every leaf the
  classification compares against receiver state, are accepted or refused
  together. Its converse reading is the residual: the leaves it does not
  mention move the decision only through the gate.
-/
theorem accept_determined_by_gate_and_compared_leaves
    (st st' : Statement) (rs : ReceiverState)
    (hGate : rs.statementGate st = rs.statementGate st')
    (hAgree : ∀ f : Field, comparedAgainstReceiver (classify f) = true -> st f = st' f) :
    accept st rs = accept st' rs := by
  have hPointwise : fieldAgrees st rs = fieldAgrees st' rs := by
    funext f
    rw [fieldAgrees, fieldAgrees]
    cases hEqBound : comparedForEquality (classify f) with
    | some against =>
      have hSame : st f = st' f :=
        hAgree f (by simp [comparedAgainstReceiver, hEqBound])
      rw [hSame]
    | none =>
      cases hDomainBound : comparedWithinDomain (classify f) with
      | some against =>
        have hSame : st f = st' f :=
          hAgree f (by simp [comparedAgainstReceiver, hDomainBound])
        rw [hSame]
      | none => rfl
  rw [accept, accept, hPointwise, hGate]

/--
  The residual, stated with the bound the shipped receiver actually has:
  replacing a leaf the classification compares against nothing the receiver
  holds leaves the decision unchanged **provided the statement gate's verdict
  does not move**. That proviso is not a formality. The gate carries each
  leaf's declared shape, and a replacement outside it is refused: sixty-four
  lowercase hex characters for the admission report digest, a non-empty string
  for each policy identity and version, one of four labels for the
  cross-organization visibility. Inside the declared shape the receiver reads
  nothing, and that is what an adversary who can produce both signatures
  chooses freely.
-/
theorem residual_substitution_preserves_acceptance
    (st : Statement) (rs : ReceiverState) (g : Field) (replacement : String)
    (hResidual : comparedAgainstReceiver (classify g) = false)
    (hGate : rs.statementGate (fun f => if f = g then replacement else st f)
               = rs.statementGate st) :
    accept (fun f => if f = g then replacement else st f) rs = accept st rs := by
  refine accept_determined_by_gate_and_compared_leaves _ _ rs hGate ?_
  intro f hCompared
  have hne : f ≠ g := by
    intro hEq
    rw [hEq, hResidual] at hCompared
    simp at hCompared
  simp [hne]

end Chio.Treaty.AdmissionBinding
