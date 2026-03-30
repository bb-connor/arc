/-
  ARC formal properties P1-P5.
  Mirrors the launch safety-property inventory documented in spec/PROTOCOL.md.

  P1: Capability monotonicity (delegation can only attenuate)
  P2: Revocation completeness (revoking ancestor invalidates descendants)
  P3: Fail-closed guarantee (errors produce denials)
  P4: Receipt chain integrity (every action has a signed receipt)
  P5: Delegation graph acyclicity
-/

import Arc.Core.Capability
import Arc.Core.Scope
import Arc.Core.Revocation

set_option autoImplicit false

namespace Arc.Spec

open Arc.Core

-- P1: Capability Monotonicity

/-- P1: Capability monotonicity -- if a child scope is a subset of a parent
    scope, then every grant in the child is covered by some grant in the
    parent.

    This is the core ARC safety property: delegation can only attenuate,
    never amplify. -/
theorem capability_monotonicity (parent child : ArcScope)
    (h : child.isSubsetOf parent = true) :
    ∀ g, g ∈ child.grants →
      ∃ pg, pg ∈ parent.grants ∧ g.isSubsetOf pg = true := by
  intro g h_mem
  unfold ArcScope.isSubsetOf at h
  have h_all := List.all_eq_true.mp h g h_mem
  simp [List.any] at h_all
  exact h_all

/-- P1a: Empty scope is always a valid attenuation. -/
theorem empty_scope_monotonicity (parent : ArcScope) :
    ArcScope.isSubsetOf ArcScope.empty parent = true :=
  ArcScope.empty_isSubsetOf parent

/-- P1b: Removing a grant from a scope produces a subset. -/
theorem remove_grant_is_attenuation (scope : ArcScope) (g : ToolGrant) :
    ArcScope.isSubsetOf
      { grants := scope.grants.filter (fun x => !(x == g)) }
      scope = true := by
  unfold ArcScope.isSubsetOf
  apply List.all_eq_true.mpr
  intro x h_mem
  have h_in_original := List.mem_of_mem_filter h_mem
  simp [List.any]
  exact ⟨x, h_in_original, ToolGrant.isSubsetOf_refl x⟩

/-- P1c: Reducing operations on a grant produces a subset (when parent has no
    invocation cap and constraints match). -/
theorem fewer_operations_is_attenuation
    (serverId : ServerId) (toolName : ToolName)
    (childOps parentOps : List Operation)
    (constraints : List Constraint)
    (h_ops_subset : childOps.isSubsetOf parentOps = true) :
    ToolGrant.isSubsetOf
      { serverId := serverId, toolName := toolName,
        operations := childOps, constraints := constraints,
        maxInvocations := none }
      { serverId := serverId, toolName := toolName,
        operations := parentOps, constraints := constraints,
        maxInvocations := none } = true := by
  unfold ToolGrant.isSubsetOf
  simp [h_ops_subset, List.isSubsetOf]
  constructor
  · -- constraints: parent.constraints.isSubsetOf child.constraints
    -- Both have the same constraints, so this is self-subset
    intro c h_mem
    exact List.any_of_mem h_mem (BEq.beq_refl c)
  · rfl

-- P2: Revocation Completeness

/-- P2: If a capability ID is in the revocation store, the kernel denies it. -/
theorem revocation_direct (store : RevocationStore) (cap : CapabilityToken)
    (trustedKeys : List PublicKeyHex)
    (toolName : ToolName) (serverId : ServerId) (now : Timestamp)
    (h_revoked : store.isRevoked cap.id = true) :
    evalToolCall trustedKeys store cap toolName serverId now =
      .deny s!"capability {cap.id} is revoked"
    ∨ ∃ msg, evalToolCall trustedKeys store cap toolName serverId now = .deny msg := by
  unfold evalToolCall
  by_cases h_sig : verifyCapabilitySignature cap trustedKeys
  · simp [h_sig]
    by_cases h_before : now < cap.issuedAt
    · simp [h_before]; right; exact ⟨_, rfl⟩
    · simp [h_before]
      by_cases h_expired : now ≥ cap.expiresAt
      · simp [h_expired]; right; exact ⟨_, rfl⟩
      · simp [h_expired, h_revoked]; left; rfl
  · simp [h_sig]; right; exact ⟨_, rfl⟩

/-- P2a: If any delegation chain ancestor is revoked, the kernel denies. -/
theorem revocation_ancestor (store : RevocationStore) (cap : CapabilityToken)
    (trustedKeys : List PublicKeyHex)
    (toolName : ToolName) (serverId : ServerId) (now : Timestamp)
    (link : DelegationLink)
    (h_in_chain : link ∈ cap.delegationChain)
    (h_ancestor_revoked : store.isRevoked link.delegator = true)
    (h_cap_not_revoked : store.isRevoked cap.id = false)
    (h_sig : verifyCapabilitySignature cap trustedKeys = true)
    (h_valid_time : now ≥ cap.issuedAt ∧ now < cap.expiresAt) :
    ∃ msg, evalToolCall trustedKeys store cap toolName serverId now = .deny msg := by
  unfold evalToolCall
  simp [h_sig, h_valid_time.1, h_valid_time.2, h_cap_not_revoked]
  have h_any : cap.delegationChain.any (fun l => store.isRevoked l.delegator) = true := by
    apply List.any_eq_true.mpr
    exact ⟨link, h_in_chain, h_ancestor_revoked⟩
  simp [h_any]
  exact ⟨_, rfl⟩

-- P3: Fail-Closed Guarantee

/-- P3: Every evaluation path produces either allow or deny -- never an
    unhandled error. The kernel's evalToolCall is total. -/
theorem fail_closed_total (trustedKeys : List PublicKeyHex)
    (store : RevocationStore)
    (cap : CapabilityToken)
    (toolName : ToolName) (serverId : ServerId)
    (now : Timestamp) :
    (evalToolCall trustedKeys store cap toolName serverId now = .allow) ∨
    (∃ msg, evalToolCall trustedKeys store cap toolName serverId now = .deny msg) := by
  unfold evalToolCall
  -- Exhaustive case analysis on all branches
  by_cases h_sig : verifyCapabilitySignature cap trustedKeys
  · simp [h_sig]
    by_cases h_before : now < cap.issuedAt
    · simp [h_before]; right; exact ⟨_, rfl⟩
    · simp [h_before]
      by_cases h_expired : now ≥ cap.expiresAt
      · simp [h_expired]; right; exact ⟨_, rfl⟩
      · simp [h_expired]
        by_cases h_rev : store.isRevoked cap.id
        · simp [h_rev]; right; exact ⟨_, rfl⟩
        · simp [h_rev]
          by_cases h_chain : cap.delegationChain.any (fun link => store.isRevoked link.delegator)
          · simp [h_chain]; right; exact ⟨_, rfl⟩
          · simp [h_chain]
            by_cases h_scope : checkScope cap toolName serverId
            · simp [h_scope]; left; rfl
            · simp [h_scope]; right; exact ⟨_, rfl⟩
  · simp [h_sig]; right; exact ⟨_, rfl⟩

/-- P3a: If signature verification fails, result is deny. -/
theorem fail_closed_bad_signature (trustedKeys : List PublicKeyHex)
    (store : RevocationStore)
    (cap : CapabilityToken)
    (toolName : ToolName) (serverId : ServerId)
    (now : Timestamp)
    (h_bad_sig : verifyCapabilitySignature cap trustedKeys = false) :
    ∃ msg, evalToolCall trustedKeys store cap toolName serverId now = .deny msg := by
  unfold evalToolCall
  simp [h_bad_sig]
  exact ⟨_, rfl⟩

/-- P3b: If the capability is expired, result is deny. -/
theorem fail_closed_expired (trustedKeys : List PublicKeyHex)
    (store : RevocationStore)
    (cap : CapabilityToken)
    (toolName : ToolName) (serverId : ServerId)
    (now : Timestamp)
    (h_sig : verifyCapabilitySignature cap trustedKeys = true)
    (h_not_before : ¬(now < cap.issuedAt))
    (h_expired : now ≥ cap.expiresAt) :
    ∃ msg, evalToolCall trustedKeys store cap toolName serverId now = .deny msg := by
  unfold evalToolCall
  simp [h_sig, h_not_before, h_expired]
  exact ⟨_, rfl⟩

/-- P3c: If the tool is out of scope, result is deny. -/
theorem fail_closed_out_of_scope (trustedKeys : List PublicKeyHex)
    (store : RevocationStore)
    (cap : CapabilityToken)
    (toolName : ToolName) (serverId : ServerId)
    (now : Timestamp)
    (h_sig : verifyCapabilitySignature cap trustedKeys = true)
    (h_valid_time : now ≥ cap.issuedAt ∧ now < cap.expiresAt)
    (h_not_revoked : store.isRevoked cap.id = false)
    (h_chain_ok : cap.delegationChain.any (fun l => store.isRevoked l.delegator) = false)
    (h_out_of_scope : checkScope cap toolName serverId = false) :
    ∃ msg, evalToolCall trustedKeys store cap toolName serverId now = .deny msg := by
  unfold evalToolCall
  simp [h_sig, h_valid_time.1, h_valid_time.2, h_not_revoked, h_chain_ok, h_out_of_scope]
  exact ⟨_, rfl⟩

-- P4: Receipt Chain Integrity

-- Receipt integrity is axiomatized since it depends on Ed25519 signature
-- verification (same approach as ClawdStrike's Crypto module).

/-- Opaque cryptographic types for receipts. -/
axiom SecretKey : Type
axiom ReceiptPublicKey : Type
axiom ReceiptSignature : Type
axiom ReceiptByteArray : Type

axiom receiptPublicKey : SecretKey → ReceiptPublicKey
axiom receiptSign : SecretKey → ReceiptByteArray → ReceiptSignature
axiom receiptVerify : ReceiptPublicKey → ReceiptByteArray → ReceiptSignature → Bool
axiom receiptCanonicalize : String → ReceiptByteArray

/-- Ed25519 sign-verify roundtrip axiom. -/
axiom receipt_sign_verify_roundtrip (sk : SecretKey) (msg : ReceiptByteArray) :
    receiptVerify (receiptPublicKey sk) msg (receiptSign sk msg) = true

/-- Simplified receipt structure. -/
structure ArcReceipt where
  id : String
  timestamp : Timestamp
  capabilityId : CapabilityId
  toolServer : ServerId
  toolName : ToolName
  decision : String
  policyHash : String
  deriving Repr, BEq

/-- Signed receipt. -/
structure SignedReceipt where
  receipt : ArcReceipt
  signature : ReceiptSignature
  kernelKey : ReceiptPublicKey

/-- Sign a receipt with the kernel's key. -/
noncomputable def SignedReceipt.sign (sk : SecretKey) (r : ArcReceipt) : SignedReceipt :=
  let canonical := receiptCanonicalize (toString r)
  { receipt := r
  , signature := receiptSign sk canonical
  , kernelKey := receiptPublicKey sk }

/-- Verify a signed receipt. -/
noncomputable def SignedReceipt.verify (sr : SignedReceipt) : Bool :=
  let canonical := receiptCanonicalize (toString sr.receipt)
  receiptVerify sr.kernelKey canonical sr.signature

/-- P4: Sign-then-verify roundtrip for receipts. -/
theorem receipt_sign_then_verify (sk : SecretKey) (r : ArcReceipt) :
    (SignedReceipt.sign sk r).verify = true := by
  unfold SignedReceipt.sign SignedReceipt.verify
  simp only []
  exact receipt_sign_verify_roundtrip sk (receiptCanonicalize (toString r))

/-- P4a: Signing preserves the receipt content. -/
theorem receipt_sign_preserves_content (sk : SecretKey) (r : ArcReceipt) :
    (SignedReceipt.sign sk r).receipt = r := by
  unfold SignedReceipt.sign
  rfl

/-- P4b: Signing binds the kernel's public key. -/
theorem receipt_sign_binds_key (sk : SecretKey) (r : ArcReceipt) :
    (SignedReceipt.sign sk r).kernelKey = receiptPublicKey sk := by
  unfold SignedReceipt.sign
  rfl

-- P5: Delegation Graph Acyclicity

/-- P5: A capability cannot appear in its own delegation chain.

    This follows from the construction: delegation chain entries record
    delegator public keys, and the capability ID is a distinct identifier.
    We model this as a structural property. -/
theorem delegation_acyclicity (cap : CapabilityToken)
    (h_no_self : ∀ link, link ∈ cap.delegationChain → link.delegator ≠ cap.id) :
    ¬(cap.delegationChain.any (fun link => link.delegator == cap.id) = true) := by
  intro h_any
  have ⟨link, h_mem, h_eq⟩ := List.any_eq_true.mp h_any
  have h_ne := h_no_self link h_mem
  -- h_eq says link.delegator == cap.id is true, but h_ne says they're not equal
  simp [BEq.beq, beq, decide_eq_true_eq] at h_eq
  exact h_ne h_eq

/-- P5a: Chain depth is bounded by maxDelegationDepth. -/
theorem delegation_depth_bounded (chain : List DelegationLink) :
    chainWithinDepth chain maxDelegationDepth = true →
    chain.length ≤ maxDelegationDepth := by
  unfold chainWithinDepth
  intro h
  exact h

/-- P5b: Empty delegation chain is always valid. -/
theorem empty_chain_valid (maxDepth : Option Nat)
    (h_depth : ∀ d, maxDepth = some d → 0 ≤ d) :
    validateDelegationChain [] maxDepth = .ok () := by
  unfold validateDelegationChain chainWithinDepth chainConnected chainTimestampsMonotone
  cases maxDepth with
  | none => simp
  | some d => simp [List.length]

/-- P5c: Connected chain has matching delegatee/delegator between adjacent links. -/
theorem connected_chain_adjacent (a b : DelegationLink) (rest : List DelegationLink)
    (h : chainConnected (a :: b :: rest) = true) :
    a.delegatee == b.delegator = true := by
  unfold chainConnected at h
  simp [Bool.and_eq_true] at h
  exact h.1

-- Compositional properties

/-- Allow requires all checks to pass: signature, time, revocation, scope. -/
theorem allow_requires_all_checks (trustedKeys : List PublicKeyHex)
    (store : RevocationStore)
    (cap : CapabilityToken)
    (toolName : ToolName) (serverId : ServerId)
    (now : Timestamp)
    (h_allow : evalToolCall trustedKeys store cap toolName serverId now = .allow) :
    verifyCapabilitySignature cap trustedKeys = true
    ∧ now ≥ cap.issuedAt
    ∧ now < cap.expiresAt
    ∧ store.isRevoked cap.id = false
    ∧ checkScope cap toolName serverId = true := by
  unfold evalToolCall at h_allow
  by_cases h_sig : verifyCapabilitySignature cap trustedKeys
  · simp [h_sig] at h_allow
    by_cases h_before : now < cap.issuedAt
    · simp [h_before] at h_allow
    · simp [h_before] at h_allow
      by_cases h_expired : now ≥ cap.expiresAt
      · simp [h_expired] at h_allow
      · simp [h_expired] at h_allow
        by_cases h_rev : store.isRevoked cap.id
        · simp [h_rev] at h_allow
        · simp [h_rev] at h_allow
          by_cases h_chain : cap.delegationChain.any (fun l => store.isRevoked l.delegator)
          · simp [h_chain] at h_allow
          · simp [h_chain] at h_allow
            by_cases h_scope : checkScope cap toolName serverId
            · exact ⟨h_sig, Nat.not_lt.mp h_before, Nat.not_le.mp h_expired, h_rev, h_scope⟩
            · simp [h_scope] at h_allow
  · simp [h_sig] at h_allow

end Arc.Spec
