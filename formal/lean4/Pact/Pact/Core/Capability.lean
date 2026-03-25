/-
  Core type definitions: CapabilityToken, PactScope, ToolGrant, Operation,
  Constraint, DelegationLink, Attenuation.
  Mirrors: pact-core/src/capability.rs
-/

set_option autoImplicit false

namespace Pact.Core

abbrev ServerId := String
abbrev ToolName := String
abbrev ConstraintValue := String
abbrev PublicKeyHex := String
abbrev CapabilityId := String
abbrev Timestamp := Nat

/-- Mirrors: Operation in capability.rs -/
inductive Operation where
  | invoke
  | readResult
  | delegate
  deriving Repr, BEq, DecidableEq, Inhabited

/-- Mirrors: Constraint in capability.rs -/
inductive Constraint where
  | pathPrefix : String → Constraint
  | domainExact : String → Constraint
  | domainGlob : String → Constraint
  | regexMatch : String → Constraint
  | maxLength : Nat → Constraint
  | custom : String → String → Constraint
  deriving Repr, BEq, DecidableEq

/-- Mirrors: ToolGrant in capability.rs -/
structure ToolGrant where
  serverId : ServerId
  toolName : ToolName
  operations : List Operation
  constraints : List Constraint
  maxInvocations : Option Nat
  deriving Repr, BEq

/-- Mirrors: PactScope in capability.rs -/
structure PactScope where
  grants : List ToolGrant
  deriving Repr, BEq

/-- Mirrors: Attenuation in capability.rs -/
inductive Attenuation where
  | removeTool : ServerId → ToolName → Attenuation
  | removeOperation : ServerId → ToolName → Operation → Attenuation
  | addConstraint : ServerId → ToolName → Constraint → Attenuation
  | reduceBudget : ServerId → ToolName → Nat → Attenuation
  | shortenExpiry : Timestamp → Attenuation
  deriving Repr, BEq

/-- Mirrors: DelegationLink in capability.rs (signature opaque). -/
structure DelegationLink where
  delegator : PublicKeyHex
  delegatee : PublicKeyHex
  attenuations : List Attenuation
  timestamp : Timestamp
  deriving Repr, BEq

/-- Mirrors: CapabilityToken in capability.rs.
    Signature and cryptographic fields are axiomatized in Crypto. -/
structure CapabilityToken where
  id : CapabilityId
  issuer : PublicKeyHex
  subject : PublicKeyHex
  scope : PactScope
  issuedAt : Timestamp
  expiresAt : Timestamp
  delegationChain : List DelegationLink
  deriving Repr, BEq

/-- Mirrors: CapabilityToken::is_valid_at (issued_at <= now < expires_at). -/
def CapabilityToken.isValidAt (cap : CapabilityToken) (now : Timestamp) : Bool :=
  now ≥ cap.issuedAt && now < cap.expiresAt

/-- Mirrors: CapabilityToken::is_expired_at (now >= expires_at). -/
def CapabilityToken.isExpiredAt (cap : CapabilityToken) (now : Timestamp) : Bool :=
  now ≥ cap.expiresAt

/-- Mirrors: KernelConfig.max_delegation_depth (default). -/
def maxDelegationDepth : Nat := 32

end Pact.Core
