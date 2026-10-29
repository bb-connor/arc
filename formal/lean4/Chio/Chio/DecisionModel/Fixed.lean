/-
  Q16.16 checked multiplication from `crates/core/chio-fixed/src/q16.rs`.

  A value is its signed 32-bit bit pattern read as an integer; the real number
  it denotes is that integer divided by 2^16. `checkedMul` multiplies the two
  patterns exactly, floors the product divided by 2^16, and refuses a result
  outside the signed 32-bit range, as `Q16_16::checked_mul` does with an i64
  product, an arithmetic right shift and `i32::try_from`.
-/

set_option autoImplicit false

namespace Chio.DecisionModel.Fixed

/-- Smallest signed 32-bit bit pattern. -/
def minBits : Int := -2147483648

/-- Largest signed 32-bit bit pattern. -/
def maxBits : Int := 2147483647

/-- The scale of one unit: 2^16. -/
def one : Int := 65536

/-- Floor of the exact product divided by 2^16, refused outside the i32 range. -/
def checkedMul (a b : Int) : Option Int :=
  if minBits ≤ (a * b) / one ∧ (a * b) / one ≤ maxBits then some ((a * b) / one) else none

/-- `checkedMul` returns exactly the floor of `a * b / 2^16` when that floor fits
in a signed 32-bit pattern, and refuses otherwise. -/
theorem checked_mul_spec (a b q : Int) :
    checkedMul a b = some q ↔
      (q * one ≤ a * b ∧ a * b < (q + 1) * one) ∧ minBits ≤ q ∧ q ≤ maxBits := by
  unfold checkedMul minBits maxBits one
  generalize a * b = p
  by_cases h : -2147483648 ≤ p / 65536 ∧ p / 65536 ≤ 2147483647
  · rw [if_pos h]
    constructor
    · intro hq
      cases hq
      omega
    · intro ⟨⟨hlo, hhi⟩, _⟩
      have : p / 65536 = q := by omega
      rw [this]
  · rw [if_neg h]
    constructor
    · intro hq
      cases hq
    · intro ⟨⟨hlo, hhi⟩, hr⟩
      exact absurd (by omega) h

/-- A refusal happens exactly when the floored product leaves the i32 range. -/
theorem checked_mul_none_iff (a b : Int) :
    checkedMul a b = none ↔ ¬ (minBits ≤ (a * b) / one ∧ (a * b) / one ≤ maxBits) := by
  unfold checkedMul
  by_cases h : minBits ≤ (a * b) / one ∧ (a * b) / one ≤ maxBits
  · simp [h]
  · simp [h]

end Chio.DecisionModel.Fixed
