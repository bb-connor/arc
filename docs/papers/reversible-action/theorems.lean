/-
  Draft theorem statements for the reversible-action paper.

  This file is a PLANNING ARTIFACT. It is not registered in any lakefile and
  is not part of the proof root (`formal/lean4/Chio`). It is checked by hand
  with `lake env lean` from `formal/lean4/Chio` against the syntactic treaty
  model in `Chio.Treaty.Intersection` and `Chio.Treaty.PredicateLang`:
  constitutions are `SyntacticConstitution`, admission inputs are
  `AdmissionView`, and `BackwardRefines new old domain` is refinement on an
  explicit finite domain.

      cd formal/lean4/Chio && lake env lean \
        ../../../docs/papers/reversible-action/theorems.lean

  Companion paper directory: docs/papers/reversible-action/.

  Relationship to the parent substrate:
    The amendment side conditions enactment at the type level on a
    `BackwardRefines` witness carried inside `ConstitutionalDelta`. The
    response side is left to the admission predicate; no positive
    type-level invariant is imposed on enforcement acts. The construction
    below lifts the response side to a similar discipline: an executive
    action carries a positive TTL and an optional rollback receipt, and the
    trajectory of constitutions induced by a sequence of TTL-bounded
    amendments is the object of the composition theorem.

  Status of each declaration (none is closed by `sorry`):
    - `bounded_executive_action_carries_ttl_and_rollback_slot`: projection
      of the `ttlPositive` field; definitional bridge.
    - `rollback_closes_or_ttl_window_active`: case split on the TTL window;
      definitional bridge.
    - `ttl_bounded_amendment_chain_preserves_baseline` (headline): proved
      pointwise per amendment by a case split on `activeAt` and composition
      of the two refinement hypotheses on the shared finite domain.
    - `rollback_admission_composes_with_refinement`: one hypothesis
      discharge; the content is the `GlobalSynBackwardRefines` premise.
    - `closure_to_syntactic_admission_bridge`: instance of the proof-root
      theorem `Chio.Treaty.PredicateLang.bridge_pointwise`
      (`formal/theorem-inventory.json` id `treaty.bridge.pointwise`).
    - `destructive_action_requires_bilateral_admission`: instance of the
      proof-root theorem
      `Chio.Treaty.treaty_admission_iff_predicate_intersection`.
-/

import Chio.Treaty.Intersection
import Chio.Treaty.PredicateLang
import Chio.Treaty.BridgeEquivalence

set_option autoImplicit false

namespace Chio.ReversibleAction

open Chio.Treaty

/-! ## Substrate -/

/-- Opaque receipt identifier carried by executive-action and rollback
    receipts. -/
abbrev ReceiptId := String

/-- Duration of an executive action's authorized window, in seconds. -/
abbrev Duration := Nat

/-- Wall-clock instant at which a receipt was signed, in seconds since epoch. -/
abbrev Instant := Nat

/-- Action class taxonomy. Reversible variants carry an OS-executor pair
    (forward and inverse). Destructive variants require bilateral
    cosignature at admission. -/
inductive ActionKind where
  | observation
  | restrictEgress
  | quarantineFile
  | disablePersistence
  | suspendProcessTree
  | terminateProcessTree
  | isolateNetwork
  | revokeGrant
  deriving Repr, BEq, DecidableEq

/-- Reversible variants are the four with rollback executors in the
    deployment instance: file quarantine, persistence disable, process-
    tree suspend, and egress restriction. -/
def ActionKind.reversible : ActionKind -> Bool
  | .quarantineFile => true
  | .disablePersistence => true
  | .suspendProcessTree => true
  | .restrictEgress => true
  | _ => false

/-- Destructive variants require bilateral cosignature at admission. -/
def ActionKind.destructive : ActionKind -> Bool
  | .terminateProcessTree => true
  | .isolateNetwork => true
  | .revokeGrant => true
  | _ => false

/-- A rollback receipt closes an action by referencing the original
    execution receipt id and the executor key that signed the rollback. -/
structure RollbackReceipt where
  rollbackOf : ReceiptId
  rolledBackAt : Instant
  executorKey : String
  deriving Repr, BEq, DecidableEq, Inhabited

/-- An executive action carries a positive TTL witness, the action class,
    and an optional rollback receipt. An unbounded act is not constructable
    (the `ttlPositive` field forces the type-level invariant). -/
structure ExecutiveAction where
  receiptId : ReceiptId
  issuedAt : Instant
  ttl : Duration
  ttlPositive : 0 < ttl
  actionKind : ActionKind
  rollback : Option RollbackReceipt

/-- Expiry derived from issued-at plus TTL. -/
def ExecutiveAction.expiresAt (act : ExecutiveAction) : Instant :=
  act.issuedAt + act.ttl

/-- Closed at `t` iff a rollback receipt exists with `rolledBackAt <= t`,
    or the TTL window has elapsed by `t`. -/
def ExecutiveAction.closedAt (act : ExecutiveAction) (t : Instant) : Prop :=
  (∃ rb : RollbackReceipt, act.rollback = some rb ∧ rb.rolledBackAt ≤ t)
    ∨ act.expiresAt ≤ t

/-! ## Definitional bridges -/

/--
  Candidate 1. The type-level invariant that a witness carries positive TTL.

  This discharges by projection on `ttlPositive`. It is the response-side
  analog of `amendment_admissible_iff_backward_refinement` and carries the
  same criticism: it restates a constructor precondition as a property of
  outputs. It is retained as a definitional bridge documenting the
  type-level discipline, not as the headline theorem.
-/
theorem bounded_executive_action_carries_ttl_and_rollback_slot
    (act : ExecutiveAction) :
    0 < act.ttl := act.ttlPositive

/--
  Candidate 2. Every action is either closed at `t` or still inside its TTL
  window at `t`.

  This discharges by a case split on `act.expiresAt ≤ t`; the rollback arm
  of `closedAt` is never needed. Retained as a definitional bridge.
-/
theorem rollback_closes_or_ttl_window_active
    (act : ExecutiveAction) (t : Instant) :
    act.closedAt t ∨ t < act.expiresAt := by
  by_cases h : act.expiresAt ≤ t
  · exact Or.inl (Or.inr h)
  · exact Or.inr (Nat.lt_of_not_le h)

/-! ## Candidate 3: load-bearing composition -/

/--
  A TTL-bounded amendment: a `ConstitutionalDelta` paired with a positive
  TTL witnessing that the amendment self-reverts after the duration
  elapses unless re-enacted. The pre-amendment constitution returns at
  `ttl` seconds past the `issuedAt`.
-/
structure TtlBoundedAmendment where
  delta : ConstitutionalDelta
  issuedAt : Instant
  ttl : Duration
  ttlPositive : 0 < ttl

/--
  The constitution active at time `t` under a TTL-bounded amendment is
  `delta.new` while inside the TTL window and `delta.old` after the
  window expires (the auto-reversion). This is the substrate model of
  the TTL scheduler.
-/
def TtlBoundedAmendment.activeAt (a : TtlBoundedAmendment) (t : Instant) :
    Constitution :=
  if a.issuedAt + a.ttl ≤ t then a.delta.old else a.delta.new

/--
  Candidate 3. The TTL-bounded amendment chain preserves backward
  refinement against a baseline constitution, on one explicit finite
  admission domain, at every time point.

  `BackwardRefines new old domain` is the substrate's domain-scoped
  refinement: every view in `domain` admitted by `new` is admitted by
  `old`. The statement is finite-domain, matching the witness a checked
  `ConstitutionalDelta` carries; it says nothing about views outside
  `domain`.

  Proof shape: pointwise over `a ∈ chain` (a universally quantified
  conclusion, not an induction over an evolving state). For each `a`,
  case-split on whether `t` falls inside or outside `a`'s TTL window.
  Outside the window, `a.activeAt t = a.delta.old`, and the conclusion is
  the post-expiry hypothesis `h_chain_base a` applied directly. Inside the
  window, `a.activeAt t = a.delta.new`, and a view admitted by
  `a.delta.new` is admitted by `a.delta.old` (`h_chain_refines a`) and
  hence by the baseline (`h_chain_base a`).

  The hypothesis `h_chain_base` is the `BackwardRefines a.delta.old
  baseline domain` form (each step's pre-amendment constitution
  backward-refines the baseline). An equality form (`a.delta.old =
  baseline`) would collapse the post-expiry arm to reflexivity; the
  refinement form keeps both arms substantive.
-/
theorem ttl_bounded_amendment_chain_preserves_baseline
    (baseline : Constitution)
    (chain : List TtlBoundedAmendment)
    (domain : List AdmissionView)
    (h_chain_base :
      ∀ a ∈ chain, BackwardRefines a.delta.old baseline domain)
    (h_chain_refines :
      ∀ a ∈ chain, BackwardRefines a.delta.new a.delta.old domain)
    (t : Instant) :
    ∀ a ∈ chain,
      BackwardRefines (a.activeAt t) baseline domain := by
  intro a ha
  unfold TtlBoundedAmendment.activeAt
  split
  · exact h_chain_base a ha
  · intro view hMember hNew
    exact h_chain_base a ha view hMember (h_chain_refines a ha view hMember hNew)

/-! ## Candidate 4: rollback receipt admissibility under refinement -/

/--
  An executive action is admitted on one admission view; the rollback that
  closes the action is admitted on another. The pair (`enactmentView`,
  `rollbackView`) is the load-bearing structural object. A polity admits
  each iff its constitution's predicates accept that view.
-/
structure ActionReceiptPair where
  enactmentView : AdmissionView
  rollbackView : AdmissionView
  deriving Repr, BEq, DecidableEq, Inhabited

/--
  Candidate 4. A rollback receipt admitted under the post-amendment
  constitution remains admitted under the pre-amendment constitution,
  given the global refinement premise.

  The proof consumes `h_refines` as a function applied to the rollback
  view (a single hypothesis discharge, not a structural unfold of the
  goal). The premise is `GlobalSynBackwardRefines`, the unrestricted form;
  a checked `ConstitutionalDelta` carries only the domain-scoped
  `BackwardRefines`, so composing this reduction with Candidate 3 requires
  `pair.rollbackView` to lie in that delta's domain.
-/
theorem rollback_admission_composes_with_refinement
    (pair : ActionReceiptPair)
    (cOld cNew : Constitution)
    (h_refines : PredicateLang.GlobalSynBackwardRefines cNew cOld)
    (h_new_admits_rollback :
      PredicateLang.admits cNew pair.rollbackView = true) :
    PredicateLang.admits cOld pair.rollbackView = true :=
  h_refines pair.rollbackView h_new_admits_rollback

/--
  Closure-to-syntactic bridge. Admission under the closure representation
  of a syntactic constitution agrees pointwise with the decidable `admits`
  predicate. This is an instance of the proof-root theorem
  `Chio.Treaty.PredicateLang.bridge_pointwise`; it is restated here only so
  that Candidates 3 and 4 can be read against the closure model the
  substrate keeps under `Chio.Treaty.Legacy`.
-/
theorem closure_to_syntactic_admission_bridge
    (c : Constitution) (view : AdmissionView) :
    Chio.Treaty.Legacy.constitutionAllows (PredicateLang.toClosure c) view =
      PredicateLang.admits c view :=
  PredicateLang.bridge_pointwise c view

/-! ## Candidate 5: bilateral admission of destructive variants -/

/--
  A bilateral envelope binds one admission view to a destructive action
  under a bilateral treaty. The substrate already encodes bilateral
  admission via the proof-root theorem
  `treaty_admission_iff_predicate_intersection`; the candidate below names
  the response-side specialization.
-/
structure BilateralEnvelope where
  view : AdmissionView
  treaty : BilateralTreaty
  actionKind : ActionKind
  destructiveWitness : actionKind.destructive = true

/--
  Candidate 5. A destructive action admits only if both the device polity
  and the operator polity admit the corresponding view. This is
  `treaty_admission_iff_predicate_intersection` specialized to the
  destructive `ActionKind` subclass; the novelty is the typed envelope, not
  the underlying theorem.
-/
theorem destructive_action_requires_bilateral_admission
    (env : BilateralEnvelope) :
    treatyAdmits env.treaty env.view = true ↔
      treatyPredicateIntersection env.treaty env.view = true :=
  treaty_admission_iff_predicate_intersection env.treaty env.view

end Chio.ReversibleAction
