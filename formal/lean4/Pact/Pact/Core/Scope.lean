/-
  Scope subsumption logic: ToolGrant.isSubsetOf, PactScope.isSubsetOf.
  Mirrors: pact-core/src/capability.rs (ToolGrant::is_subset_of, PactScope::is_subset_of)

  This is the core of PACT's capability monotonicity guarantee.
-/

import Pact.Core.Capability

set_option autoImplicit false

namespace Pact.Core

/-- Check if every element of `child` appears in `parent`. -/
def List.isSubsetOf [BEq α] (child parent : List α) : Bool :=
  child.all (fun c => parent.any (fun p => c == p))

/-- Mirrors: ToolGrant::is_subset_of in capability.rs.

    A child grant is a subset when:
    - It targets the same server.
    - Parent tool is "*" (wildcard) or matches child tool.
    - Child operations are a subset of parent operations.
    - If parent has an invocation cap, child must too and child <= parent.
    - Every parent constraint appears in child (child is more restrictive). -/
def ToolGrant.isSubsetOf (child parent : ToolGrant) : Bool :=
  -- Same server
  child.serverId == parent.serverId
  -- Tool name match (wildcard or exact)
  && (parent.toolName == "*" || child.toolName == parent.toolName)
  -- Operations subset
  && child.operations.isSubsetOf parent.operations
  -- Invocation budget
  && (match parent.maxInvocations with
      | none => true  -- parent uncapped, any child is fine
      | some parentMax =>
        match child.maxInvocations with
        | none => false  -- child uncapped but parent is capped
        | some childMax => childMax ≤ parentMax)
  -- Constraints: parent's constraints must all appear in child
  && parent.constraints.isSubsetOf child.constraints

/-- Mirrors: PactScope::is_subset_of in capability.rs.

    Returns true if every grant in `child` is covered by some grant in `parent`. -/
def PactScope.isSubsetOf (child parent : PactScope) : Bool :=
  child.grants.all (fun cg =>
    parent.grants.any (fun pg => cg.isSubsetOf pg))

/-- The empty scope: no grants at all. -/
def PactScope.empty : PactScope := { grants := [] }

/-- Empty scope is a subset of any scope. -/
theorem PactScope.empty_isSubsetOf (parent : PactScope) :
    PactScope.isSubsetOf PactScope.empty parent = true := by
  unfold PactScope.isSubsetOf PactScope.empty
  simp [List.all]

/-- Reflexivity: a scope is a subset of itself. -/
theorem ToolGrant.isSubsetOf_refl (g : ToolGrant) :
    g.isSubsetOf g = true := by
  unfold ToolGrant.isSubsetOf
  simp [List.isSubsetOf]
  constructor
  · -- operations subset: every op in g.operations is in g.operations
    intro op h_mem
    exact List.any_of_mem h_mem (BEq.beq_refl _)
  constructor
  · -- invocation budget
    cases h_max : g.maxInvocations with
    | none => simp
    | some n => simp [Nat.le_refl]
  · -- constraints: parent's constraints appear in child (parent = child)
    intro c h_mem
    exact List.any_of_mem h_mem (BEq.beq_refl _)

-- Helper: BEq.beq_refl for types with DecidableEq
private theorem BEq.beq_refl {α : Type} [BEq α] [DecidableEq α]
    [LawfulBEq α] (a : α) : (a == a) = true := by
  simp [BEq.beq]

-- Helper: if x is in a list, then `any (fun y => x == y)` is true
private theorem List.any_of_mem {α : Type} [BEq α]
    {x : α} {xs : List α} (h_mem : x ∈ xs) (h_beq : (x == x) = true) :
    xs.any (fun y => x == y) = true := by
  induction xs with
  | nil => exact absurd h_mem (List.not_mem_nil x)
  | cons a as ih =>
    simp [List.any]
    cases h_mem with
    | head => left; rw [← h_beq]; congr
    | tail _ h_tail => right; exact ih h_tail

end Pact.Core
