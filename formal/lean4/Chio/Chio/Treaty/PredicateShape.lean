/-
  Connective-preserving lift between the two bounded treaty predicate
  syntaxes.

  `ReceiptPredicate.Predicate` and `PredicateLang.Predicate` share the
  Boolean connective shape (atom, top, bot, conj, disj, neg) but interpret
  different atoms over different inputs. `ofReceipt f` transports a receipt
  predicate along an atom map `f`. The theorems below state exactly what the
  transport preserves: injectivity when `f` is injective, plain Boolean
  agreement when the atom layers agree, fail-closed denotation agreement on
  the supported-and-defined fragment, and denial whenever any mapped atom is
  unsupported or undefined for the admission projection.

  Three stronger relations are excluded because they do not exist.

  No atom map `f : ReceiptPredicate.Atom -> PredicateLang.AtomTag` paired with
  a view map `v : ReceiptView -> AdmissionView` satisfies
  `denote (.atom (f a)) (v r) = evaluateAtom a r` for every atom and receipt.
  At a fixed admission view, `fun tag => denote (.atom tag) view` is true on at
  most sixteen tags (eleven nullary gates and five `modeAtLeast` floors; every
  `unsupported` tag denotes false). Seventeen receipts with pairwise distinct
  `receiptId` values and the atoms `scopeContains r.receiptId` would require
  seventeen pairwise distinct tags that can be true, one per receipt. The
  argument does not need `f` to be injective.

  No shape-preserving map from `PredicateLang.Predicate` into
  `ReceiptPredicate.Predicate` agrees with `denote` on every predicate.
  `denote (.atom (.unsupported n)) view` and
  `denote (.neg (.atom (.unsupported n))) view` are both false, while
  `evaluate (.neg q) r = !evaluate q r` makes exactly one of a receipt predicate
  and its negation true. On the supported-and-defined fragment an encoding
  exists by materializing gate results into `evidenceDigests`; that is
  semantic bookkeeping rather than a natural injection and is not formalized.

  No field-wise injection `ReceiptView -> AdmissionView` exists.
  `ladderModeRank : Nat` has no injective image in `Option TrustMode`, and
  `receiptHash`, `liveContinuationIds`, `decision`, `failureCode`, and evidence
  digests have no counterpart in the admission projection.
-/

import Chio.Treaty.PredicateLang
import Chio.Treaty.ReceiptPredicate

set_option autoImplicit false

namespace Chio.Treaty.PredicateShape

/-- Connective-preserving lift of an atom map between the two syntaxes. -/
def ofReceipt (f : ReceiptPredicate.Atom -> PredicateLang.AtomTag) :
    ReceiptPredicate.Predicate -> PredicateLang.Predicate
  | .atom atom => .atom (f atom)
  | .top => .top
  | .bot => .bot
  | .conj left right => .conj (ofReceipt f left) (ofReceipt f right)
  | .disj left right => .disj (ofReceipt f left) (ofReceipt f right)
  | .neg predicate => .neg (ofReceipt f predicate)

/-- Atoms occurring in a receipt predicate, in left-to-right order. -/
def receiptAtoms : ReceiptPredicate.Predicate -> List ReceiptPredicate.Atom
  | .atom atom => [atom]
  | .top => []
  | .bot => []
  | .conj left right => receiptAtoms left ++ receiptAtoms right
  | .disj left right => receiptAtoms left ++ receiptAtoms right
  | .neg predicate => receiptAtoms predicate

theorem atoms_ofReceipt
    (f : ReceiptPredicate.Atom -> PredicateLang.AtomTag)
    (predicate : ReceiptPredicate.Predicate) :
    PredicateLang.atoms (ofReceipt f predicate) = (receiptAtoms predicate).map f := by
  induction predicate with
  | atom atom => rfl
  | top => rfl
  | bot => rfl
  | conj left right ihl ihr =>
      simp [ofReceipt, receiptAtoms, PredicateLang.atoms, ihl, ihr]
  | disj left right ihl ihr =>
      simp [ofReceipt, receiptAtoms, PredicateLang.atoms, ihl, ihr]
  | neg predicate ih => simp [ofReceipt, receiptAtoms, PredicateLang.atoms, ih]

theorem ofReceipt_injective
    (f : ReceiptPredicate.Atom -> PredicateLang.AtomTag)
    (hf : Function.Injective f) :
    Function.Injective (ofReceipt f) := by
  intro p q h
  induction p generalizing q with
  | atom atom =>
      cases q <;> simp [ofReceipt] at h
      exact congrArg ReceiptPredicate.Predicate.atom (hf h)
  | top =>
      cases q <;> simp [ofReceipt] at h
      rfl
  | bot =>
      cases q <;> simp [ofReceipt] at h
      rfl
  | conj left right ihl ihr =>
      cases q <;> simp [ofReceipt] at h
      rw [ihl h.1, ihr h.2]
  | disj left right ihl ihr =>
      cases q <;> simp [ofReceipt] at h
      rw [ihl h.1, ihr h.2]
  | neg predicate ih =>
      cases q <;> simp [ofReceipt] at h
      rw [ih h]

/-- The Boolean layer agrees whenever the atom layer agrees. -/
theorem eval_ofReceipt
    (f : ReceiptPredicate.Atom -> PredicateLang.AtomTag)
    (view : PredicateLang.AdmissionView)
    (receipt : ReceiptPredicate.ReceiptView)
    (hAtom : forall atom, PredicateLang.evalAtom (f atom) view =
      ReceiptPredicate.evaluateAtom atom receipt)
    (predicate : ReceiptPredicate.Predicate) :
    PredicateLang.eval (ofReceipt f predicate) view =
      ReceiptPredicate.evaluate predicate receipt := by
  induction predicate with
  | atom atom => simp [ofReceipt, PredicateLang.eval, ReceiptPredicate.evaluate, hAtom]
  | top => rfl
  | bot => rfl
  | conj left right ihl ihr =>
      simp [ofReceipt, PredicateLang.eval, ReceiptPredicate.evaluate, ihl, ihr]
  | disj left right ihl ihr =>
      simp [ofReceipt, PredicateLang.eval, ReceiptPredicate.evaluate, ihl, ihr]
  | neg predicate ih =>
      simp [ofReceipt, PredicateLang.eval, ReceiptPredicate.evaluate, ih]

theorem supported_ofReceipt
    (f : ReceiptPredicate.Atom -> PredicateLang.AtomTag)
    (hSupported : forall atom, PredicateLang.supportedAtom (f atom) = true)
    (predicate : ReceiptPredicate.Predicate) :
    PredicateLang.supported (ofReceipt f predicate) = true := by
  induction predicate with
  | atom atom => simp [ofReceipt, PredicateLang.supported, hSupported]
  | top => rfl
  | bot => rfl
  | conj left right ihl ihr => simp [ofReceipt, PredicateLang.supported, ihl, ihr]
  | disj left right ihl ihr => simp [ofReceipt, PredicateLang.supported, ihl, ihr]
  | neg predicate ih => simp [ofReceipt, PredicateLang.supported, ih]

theorem defined_ofReceipt
    (f : ReceiptPredicate.Atom -> PredicateLang.AtomTag)
    (view : PredicateLang.AdmissionView)
    (hDefined : forall atom, PredicateLang.atomDefined (f atom) view = true)
    (predicate : ReceiptPredicate.Predicate) :
    PredicateLang.defined (ofReceipt f predicate) view = true := by
  induction predicate with
  | atom atom => simp [ofReceipt, PredicateLang.defined, hDefined]
  | top => rfl
  | bot => rfl
  | conj left right ihl ihr => simp [ofReceipt, PredicateLang.defined, ihl, ihr]
  | disj left right ihl ihr => simp [ofReceipt, PredicateLang.defined, ihl, ihr]
  | neg predicate ih => simp [ofReceipt, PredicateLang.defined, ih]

/--
  Denotation agreement on the supported-and-defined image. The fail-closed
  layer of `denote` has no receipt-side counterpart, so agreement needs every
  mapped atom to be supported and defined.
-/
theorem denote_ofReceipt
    (f : ReceiptPredicate.Atom -> PredicateLang.AtomTag)
    (view : PredicateLang.AdmissionView)
    (receipt : ReceiptPredicate.ReceiptView)
    (hSupported : forall atom, PredicateLang.supportedAtom (f atom) = true)
    (hDefined : forall atom, PredicateLang.atomDefined (f atom) view = true)
    (hAtom : forall atom, PredicateLang.evalAtom (f atom) view =
      ReceiptPredicate.evaluateAtom atom receipt)
    (predicate : ReceiptPredicate.Predicate) :
    PredicateLang.denote (ofReceipt f predicate) view =
      ReceiptPredicate.evaluate predicate receipt := by
  simp [PredicateLang.denote, supported_ofReceipt f hSupported,
    defined_ofReceipt f view hDefined, eval_ofReceipt f view receipt hAtom]

/-- Fail-closed transport: an atom mapped to an unsupported tag denies the lifted predicate. -/
theorem denote_ofReceipt_unsupported
    (f : ReceiptPredicate.Atom -> PredicateLang.AtomTag)
    (view : PredicateLang.AdmissionView)
    (predicate : ReceiptPredicate.Predicate)
    (atom : ReceiptPredicate.Atom)
    (hMember : atom ∈ receiptAtoms predicate)
    (hUnsupported : PredicateLang.supportedAtom (f atom) = false) :
    PredicateLang.denote (ofReceipt f predicate) view = false := by
  apply PredicateLang.unsupported_predicate_denies
  rw [PredicateLang.supported_eq_all_atoms, atoms_ofReceipt]
  exact List.all_eq_false.mpr
    ⟨f atom, List.mem_map.mpr ⟨atom, hMember, rfl⟩, by simp [hUnsupported]⟩

/-- Fail-closed transport: an atom mapped to an undefined tag denies the lifted predicate. -/
theorem denote_ofReceipt_undefined
    (f : ReceiptPredicate.Atom -> PredicateLang.AtomTag)
    (view : PredicateLang.AdmissionView)
    (predicate : ReceiptPredicate.Predicate)
    (atom : ReceiptPredicate.Atom)
    (hMember : atom ∈ receiptAtoms predicate)
    (hUndefined : PredicateLang.atomDefined (f atom) view = false) :
    PredicateLang.denote (ofReceipt f predicate) view = false := by
  apply PredicateLang.undefined_predicate_denies
  rw [PredicateLang.defined_eq_all_atoms, atoms_ofReceipt]
  exact List.all_eq_false.mpr
    ⟨f atom, List.mem_map.mpr ⟨atom, hMember, rfl⟩, by simp [hUndefined]⟩

end Chio.Treaty.PredicateShape
