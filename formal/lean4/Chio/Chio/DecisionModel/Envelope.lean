/-
  The sealed envelope projection from
  `crates/core/chio-decision-model/src/envelope.rs`.

  An envelope is a nonempty list of admitted actions whose first element is
  the conservative fallback. `project` returns a proposal unchanged when the
  envelope admits it and the fallback otherwise, recording why. The model is
  the Rust match arm for arm; scores, `select` and the 256-action bound are
  outside it.
-/

set_option autoImplicit false

namespace Chio.DecisionModel.Envelope

/-- Why a projection returned the conservative action. -/
inductive FallbackReason
  | emptyProposal
  | proposalInfeasible
  | scorerError
  | workExhausted
  | policyUnavailable
deriving DecidableEq, Repr

/-- How a projected action relates to the proposal. -/
inductive Outcome
  | identity
  | fallback (reason : FallbackReason)
deriving DecidableEq, Repr

/-- A nonempty list of admitted actions; its head is the fallback. -/
structure Envelope (α : Type) where
  feasible : List α
  nonempty : feasible ≠ []

variable {α : Type} [DecidableEq α]

/-- The conservative action. -/
def Envelope.fallback (e : Envelope α) : α :=
  e.feasible.head e.nonempty

/-- Membership of an action in the envelope. -/
def Envelope.admits (e : Envelope α) (a : α) : Bool :=
  decide (a ∈ e.feasible)

/-- `Envelope::project`: a scorer result is either a refusal reason or an
optional proposal. -/
def Envelope.project (e : Envelope α) : Except FallbackReason (Option α) → α × Outcome
  | .ok (some a) => if e.admits a then (a, .identity) else (e.fallback, .fallback .proposalInfeasible)
  | .ok none => (e.fallback, .fallback .emptyProposal)
  | .error reason => (e.fallback, .fallback reason)

omit [DecidableEq α] in
/-- The fallback is admitted. -/
theorem fallback_mem (e : Envelope α) : e.fallback ∈ e.feasible :=
  List.head_mem e.nonempty

/-- Every projection returns an admitted action, whatever the proposal. -/
theorem project_mem (e : Envelope α) (p : Except FallbackReason (Option α)) :
    (e.project p).1 ∈ e.feasible := by
  match p with
  | .ok (some a) =>
    unfold Envelope.project
    by_cases h : e.admits a = true
    · simp only [h, if_true]
      simpa [Envelope.admits] using h
    · simp only [h]
      exact fallback_mem e
  | .ok none => exact fallback_mem e
  | .error _ => exact fallback_mem e

/-- An admitted proposal passes unchanged with an identity outcome. -/
theorem project_admitted (e : Envelope α) (a : α) (h : a ∈ e.feasible) :
    e.project (.ok (some a)) = (a, .identity) := by
  simp [Envelope.project, Envelope.admits, h]

/-- An identity outcome means the proposal was admitted and returned as is. -/
theorem project_identity_iff (e : Envelope α) (p : Except FallbackReason (Option α)) (a : α) :
    e.project p = (a, .identity) ↔ p = .ok (some a) ∧ a ∈ e.feasible := by
  constructor
  · intro hp
    match p, hp with
    | .ok (some b), hp =>
      unfold Envelope.project at hp
      by_cases h : e.admits b = true
      · simp only [h, if_true, Prod.mk.injEq] at hp
        obtain ⟨rfl, -⟩ := hp
        exact ⟨rfl, by simpa [Envelope.admits] using h⟩
      · simp [h] at hp
    | .ok none, hp => simp [Envelope.project] at hp
    | .error _, hp => simp [Envelope.project] at hp
  · rintro ⟨rfl, h⟩
    exact project_admitted e a h

/-- Projecting a projected action again changes nothing. -/
theorem project_idem (e : Envelope α) (p : Except FallbackReason (Option α)) :
    e.project (.ok (some (e.project p).1)) = ((e.project p).1, .identity) :=
  project_admitted e _ (project_mem e p)

end Chio.DecisionModel.Envelope
