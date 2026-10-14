import Std

/- Small specification, not an extraction or refinement of Rust or Solidity.
   Natural-number accounts abstract atomic rail moves; authentication, finality,
   transfer behavior and usefulness of accepted work are assumptions. -/
namespace WorkClaims

structure Account where
  free : Nat
  locked : Nat
  paid : Nat
  refunded : Nat
  deriving DecidableEq

def total (s : Account) : Nat := s.free + s.locked + s.paid + s.refunded

inductive Move : Account → Account → Prop where
  | reserve (s : Account) (q : Nat) (enough : q ≤ s.free) :
      Move s ⟨s.free - q, s.locked + q, s.paid, s.refunded⟩
  | pay (s : Account) (q : Nat) (enough : q ≤ s.locked) :
      Move s ⟨s.free, s.locked - q, s.paid + q, s.refunded⟩
  | refund (s : Account) (q : Nat) (enough : q ≤ s.locked) :
      Move s ⟨s.free, s.locked - q, s.paid, s.refunded + q⟩
  | unchanged (s : Account) : Move s s

theorem move_conserves {s t : Account} (h : Move s t) : total t = total s := by
  cases h <;> simp only [total] <;> omega

inductive Path {α : Type} (step : α → α → Prop) : α → α → Prop where
  | refl (s : α) : Path step s s
  | next {s t u : α} : Path step s t → step t u → Path step s u

theorem all_moves_conserve {s t : Account} (h : Path Move s t) : total t = total s := by
  induction h with
  | refl => rfl
  | next _ hstep ih => exact (move_conserves hstep).trans ih

theorem transfers_bounded {deposit : Nat} {t : Account}
    (h : Path Move ⟨deposit, 0, 0, 0⟩ t) : t.paid + t.refunded ≤ deposit := by
  have eq := all_moves_conserve h
  simp only [total] at eq
  omega

inductive State where
  | funded | submitted | payable | paid | rejected | timedOut | refunded
  deriving DecidableEq

/- Guards on time, role, commitment and decision are abstracted out. Removing
   guards enlarges the transition relation: these safety lemmas still hold.
   This does not establish that an implementation checks those guards. -/
inductive ClaimMove : State → State → Prop where
  | submit : ClaimMove .funded .submitted
  | accept : ClaimMove .submitted .payable
  | reject : ClaimMove .submitted .rejected
  | expireFunded : ClaimMove .funded .timedOut
  | expireSubmitted : ClaimMove .submitted .timedOut
  | pay : ClaimMove .payable .paid
  | refundRejected : ClaimMove .rejected .refunded
  | refundTimedOut : ClaimMove .timedOut .refunded
  | unchanged (s : State) : ClaimMove s s

def earned (s : State) : Prop := s = .payable ∨ s = .paid

theorem earned_step {s t : State} (h : ClaimMove s t) (e : earned s) : earned t := by
  cases h <;> simp_all [earned]

theorem earned_persists {s t : State} (h : Path ClaimMove s t) : earned s → earned t := by
  induction h with
  | refl => exact id
  | next _ hstep ih => exact fun e => earned_step hstep (ih e)

theorem earned_never_refunded {t : State} (h : Path ClaimMove .payable t) : t ≠ .refunded := by
  have e := earned_persists h (by simp [earned])
  simp only [earned] at e
  rcases e with e | e <;> simp_all

def update (claims : Nat → State) (id : Nat) (next : State) : Nat → State :=
  fun key => if key = id then next else claims key

theorem other_claim_unchanged (claims : Nat → State) (parent child : Nat)
    (different : child ≠ parent) (next : State) :
    update claims parent next child = claims child := by
  simp [update, different]

#print axioms all_moves_conserve
#print axioms transfers_bounded
#print axioms earned_never_refunded
#print axioms other_claim_unchanged
end WorkClaims
