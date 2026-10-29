/-
  Three-valued rule evaluation from `crates/guards/chio-predicate-dag`.

  `classify` mirrors `thresholds.rs`: an unattested atom is unknown, a score at
  or above `tau_pos` is true and a score below `tau_neg` is false. A rule is an
  AND of OR-clauses over possibly negated atoms and possibly negated earlier
  rules (D8), evaluated in Kleene logic in rule order as `Schedule::evaluate`
  does; a reference to a rule not yet evaluated reads unknown, as the zeroed
  rule planes do. The outcome is deny when a deny rule is true, hold when a
  deny or hold rule is unknown or a hold rule is true, and allow otherwise.

  The model works over unbounded indices and integers. Bit-plane packing,
  artifact decoding, the canonical-form checks and the work meter are outside
  it.
-/

set_option autoImplicit false

namespace Chio.DecisionModel.Kleene

/-- A Kleene truth value. -/
inductive Trit
  | true
  | false
  | unknown
deriving DecidableEq, Repr

/-- Information order: `Refines x y` holds when `x` is `y` or knows less. -/
def Refines (x y : Trit) : Prop := x = .unknown ∨ x = y

def Trit.not : Trit → Trit
  | .true => .false
  | .false => .true
  | .unknown => .unknown

def Trit.or : Trit → Trit → Trit
  | .true, _ => .true
  | _, .true => .true
  | .false, .false => .false
  | _, _ => .unknown

def Trit.and : Trit → Trit → Trit
  | .false, _ => .false
  | _, .false => .false
  | .true, .true => .true
  | _, _ => .unknown

theorem refines_refl (x : Trit) : Refines x x := Or.inr rfl

theorem not_mono {x y : Trit} (h : Refines x y) : Refines x.not y.not := by
  cases x <;> cases y <;> simp_all [Refines, Trit.not]

/-- Kleene conjunction and disjunction are monotone in the information order:
knowing less about an input never makes the output know more. -/
theorem kleene_and_or_monotone_info {x x' y y' : Trit}
    (hx : Refines x x') (hy : Refines y y') :
    Refines (x.and y) (x'.and y') ∧ Refines (x.or y) (x'.or y') := by
  cases x <;> cases x' <;> cases y <;> cases y' <;> simp_all [Refines, Trit.and, Trit.or]

/-- A literal over an atom or an earlier rule, possibly negated. -/
inductive Literal
  | atom (index : Nat) (negated : Bool)
  | rule (index : Nat) (negated : Bool)

/-- A rule is an AND of OR-clauses. -/
abbrev Rule := List (List Literal)

/-- A model: rules in evaluation order, and the indices of deny and hold rules. -/
structure Model where
  rules : List Rule
  deny : List Nat
  hold : List Nat

/-- The decision of a model. -/
inductive Outcome
  | allow
  | hold
  | deny
deriving DecidableEq, Repr

def negateIf (negated : Bool) (v : Trit) : Trit :=
  if negated then v.not else v

def literalValue (atoms rules : Nat → Trit) : Literal → Trit
  | .atom i n => negateIf n (atoms i)
  | .rule j n => negateIf n (rules j)

def clauseValue (atoms rules : Nat → Trit) (clause : List Literal) : Trit :=
  clause.foldr (fun literal acc => (literalValue atoms rules literal).or acc) .false

def ruleValue (atoms rules : Nat → Trit) (rule : Rule) : Trit :=
  rule.foldr (fun clause acc => (clauseValue atoms rules clause).and acc) .true

/-- Evaluate `rules` in order starting at index `n`; `env` holds the values of
the rules already evaluated and reads unknown everywhere else. -/
def evalFrom (atoms : Nat → Trit) : Nat → (Nat → Trit) → List Rule → (Nat → Trit)
  | _, env, [] => env
  | n, env, r :: rs =>
    evalFrom atoms (n + 1) (fun k => if k = n then ruleValue atoms env r else env k) rs

def ruleValues (m : Model) (atoms : Nat → Trit) : Nat → Trit :=
  evalFrom atoms 0 (fun _ => .unknown) m.rules

def outcomeOf (m : Model) (values : Nat → Trit) : Outcome :=
  if m.deny.any (fun j => values j == .true) then .deny
  else if m.deny.any (fun j => values j == .unknown) || m.hold.any (fun j => values j != .false)
  then .hold
  else .allow

def evaluate (m : Model) (atoms : Nat → Trit) : Outcome :=
  outcomeOf m (ruleValues m atoms)

/-- `classify` for one atom. -/
def classify (attested : Bool) (score tauNeg tauPos : Int) : Trit :=
  if !attested then .unknown
  else if tauPos ≤ score then .true
  else if score < tauNeg then .false
  else .unknown

theorem negateIf_mono (n : Bool) {x y : Trit} (h : Refines x y) :
    Refines (negateIf n x) (negateIf n y) := by
  cases n
  · exact h
  · exact not_mono h

theorem literal_mono {atoms atoms' rules rules' : Nat → Trit}
    (ha : ∀ i, Refines (atoms' i) (atoms i)) (hr : ∀ j, Refines (rules' j) (rules j))
    (l : Literal) : Refines (literalValue atoms' rules' l) (literalValue atoms rules l) := by
  cases l with
  | atom i n => exact negateIf_mono n (ha i)
  | rule j n => exact negateIf_mono n (hr j)

theorem clause_mono {atoms atoms' rules rules' : Nat → Trit}
    (ha : ∀ i, Refines (atoms' i) (atoms i)) (hr : ∀ j, Refines (rules' j) (rules j))
    (c : List Literal) : Refines (clauseValue atoms' rules' c) (clauseValue atoms rules c) := by
  induction c with
  | nil => exact refines_refl _
  | cons l ls ih =>
    exact (kleene_and_or_monotone_info (literal_mono ha hr l) ih).2

theorem rule_mono {atoms atoms' rules rules' : Nat → Trit}
    (ha : ∀ i, Refines (atoms' i) (atoms i)) (hr : ∀ j, Refines (rules' j) (rules j))
    (r : Rule) : Refines (ruleValue atoms' rules' r) (ruleValue atoms rules r) := by
  induction r with
  | nil => exact refines_refl _
  | cons c cs ih =>
    exact (kleene_and_or_monotone_info (clause_mono ha hr c) ih).1

theorem evalFrom_mono {atoms atoms' : Nat → Trit}
    (ha : ∀ i, Refines (atoms' i) (atoms i)) (rs : List Rule) :
    ∀ (n : Nat) (env env' : Nat → Trit), (∀ j, Refines (env' j) (env j)) →
      ∀ j, Refines (evalFrom atoms' n env' rs j) (evalFrom atoms n env rs j) := by
  induction rs with
  | nil => intro _ _ _ he j; exact he j
  | cons r rs ih =>
    intro n env env' he
    apply ih
    intro k
    by_cases hk : k = n
    · simp only [hk, if_true]
      exact rule_mono ha he r
    · simp only [hk, if_false]
      exact he k

/-- Evaluating with less information about the atoms gives rule values that
know no more. -/
theorem ruleValues_mono (m : Model) {atoms atoms' : Nat → Trit}
    (ha : ∀ i, Refines (atoms' i) (atoms i)) (j : Nat) :
    Refines (ruleValues m atoms' j) (ruleValues m atoms j) :=
  evalFrom_mono ha m.rules 0 _ _ (fun _ => refines_refl _) j

theorem outcome_allow_iff (m : Model) (values : Nat → Trit) :
    outcomeOf m values = .allow ↔
      (∀ j ∈ m.deny, values j = .false) ∧ (∀ j ∈ m.hold, values j = .false) := by
  unfold outcomeOf
  constructor
  · intro h
    by_cases hd : m.deny.any (fun j => values j == .true) = Bool.true
    · simp [hd] at h
    · by_cases hh : (m.deny.any (fun j => values j == .unknown) ||
          m.hold.any (fun j => values j != .false)) = Bool.true
      · simp only [hd, hh] at h
        simp at h
      · simp only [Bool.not_eq_true, Bool.or_eq_false_iff, List.any_eq_false,
          beq_iff_eq, bne_iff_ne, ne_eq, Decidable.not_not] at hd hh
        refine ⟨fun j hj => ?_, fun j hj => hh.2 j hj⟩
        have h1 := hd j hj
        have h2 := hh.1 j hj
        cases hv : values j <;> simp_all
  · rintro ⟨hd, hh⟩
    have h1 : m.deny.any (fun j => values j == .true) = Bool.false := by
      simp only [List.any_eq_false, beq_iff_eq]
      intro j hj; rw [hd j hj]; decide
    have h2 : m.deny.any (fun j => values j == .unknown) = Bool.false := by
      simp only [List.any_eq_false, beq_iff_eq]
      intro j hj; rw [hd j hj]; decide
    have h3 : m.hold.any (fun j => values j != .false) = Bool.false := by
      simp only [List.any_eq_false, bne_iff_ne, ne_eq, Decidable.not_not]
      intro j hj; exact hh j hj
    simp [h1, h2, h3]

/-- D26: widening uncertainty never admits. If evaluation with some atoms does
not allow, evaluation with atoms that know no more does not allow either. -/
theorem widen_no_admit_atoms (m : Model) {atoms atoms' : Nat → Trit}
    (ha : ∀ i, Refines (atoms' i) (atoms i)) (h : evaluate m atoms ≠ .allow) :
    evaluate m atoms' ≠ .allow := by
  intro h'
  apply h
  unfold evaluate at h' ⊢
  rw [outcome_allow_iff] at h' ⊢
  have back : ∀ j, ruleValues m atoms' j = .false → ruleValues m atoms j = .false := by
    intro j hj
    rcases ruleValues_mono m ha j with hu | he
    · rw [hj] at hu; cases hu
    · rw [← he, hj]
  exact ⟨fun j hj => back j (h'.1 j hj), fun j hj => back j (h'.2 j hj)⟩

/-- Raising `tau_pos`, lowering `tau_neg` or clearing attestation gives an atom
that knows no more, provided the original thresholds are ordered. -/
theorem classify_widen {attested attested' : Bool} {score tauNeg tauPos tauNeg' tauPos' : Int}
    (hord : tauNeg ≤ tauPos) (hatt : attested' = Bool.true → attested = Bool.true)
    (hpos : tauPos ≤ tauPos') (hneg : tauNeg' ≤ tauNeg) :
    Refines (classify attested' score tauNeg' tauPos') (classify attested score tauNeg tauPos) := by
  unfold classify Refines
  cases attested' with
  | false => simp
  | true =>
    have ha := hatt rfl
    subst ha
    by_cases h1 : tauPos' ≤ score
    · have : tauPos ≤ score := Int.le_trans hpos h1
      simp [h1, this]
    · by_cases h2 : score < tauNeg'
      · have h3 : ¬ tauPos ≤ score := by omega
        have h4 : score < tauNeg := by omega
        simp [h1, h2, h3, h4]
      · simp [h1, h2]

/-- D26 over thresholds: widening the thresholds or clearing attestation never
turns a non-allow outcome into allow. -/
theorem widen_no_admit (m : Model) (scores : Nat → Int)
    (attested attested' : Nat → Bool) (tauNeg tauPos tauNeg' tauPos' : Nat → Int)
    (hord : ∀ i, tauNeg i ≤ tauPos i)
    (hatt : ∀ i, attested' i = Bool.true → attested i = Bool.true)
    (hpos : ∀ i, tauPos i ≤ tauPos' i) (hneg : ∀ i, tauNeg' i ≤ tauNeg i)
    (h : evaluate m (fun i => classify (attested i) (scores i) (tauNeg i) (tauPos i)) ≠ .allow) :
    evaluate m (fun i => classify (attested' i) (scores i) (tauNeg' i) (tauPos' i)) ≠ .allow :=
  widen_no_admit_atoms m
    (fun i => classify_widen (hord i) (hatt i) (hpos i) (hneg i)) h

/-- One deny rule over one atom. -/
def oneAtomDeny : Model where
  rules := [[[.atom 0 false]]]
  deny := [0]
  hold := []

/-- The stronger lattice claim is false: widening can move deny to hold. With
score `1` and `tau_neg = 0`, `tau_pos = 1` denies and `tau_pos = 2` holds. -/
theorem widen_deny_to_hold_example :
    evaluate oneAtomDeny (fun _ => classify Bool.true 1 0 1) = .deny ∧
      evaluate oneAtomDeny (fun _ => classify Bool.true 1 0 2) = .hold := by
  constructor <;> rfl

end Chio.DecisionModel.Kleene
