------------------------- MODULE DecisionEnvelope -------------------------
(***************************************************************************)
(* Decision-model envelope projection and witness ordering.                *)
(* Each call evaluates a raw outcome against a nonempty feasible envelope  *)
(* that carries a fallback member. Projection keeps an admitted raw        *)
(* outcome and otherwise selects the fallback. An allow is published only  *)
(* after the decision-model witness is bound to the projected outcome.     *)
(*                                                                          *)
(* Code mapping (full cross-reference in formal/MAPPING.md):               *)
(*   - crates/core/chio-decision-model/src/envelope.rs Envelope::project   *)
(*   - crates/kernel/chio-kernel/src/receipt_support/receipt_metadata.rs   *)
(*       bind_decision_model_witness                                       *)
(*                                                                          *)
(* Non-tautology evidence:                                                 *)
(*  - formal/apalache/_negative_tests/DecisionEnvelopeNoFallback.tla       *)
(*    projects the raw outcome without the fallback. Apalache must report  *)
(*    ChosenInFeasible violated.                                           *)
(***************************************************************************)

EXTENDS Naturals, FiniteSets

CONSTANT
    \* @type: Set(Int);
    CallSet

ASSUME CallSet = 1..2

Outcomes == {"allow", "deny", "hold"}

NoOutcome == "none"

VARIABLES
    \* @type: Int -> Str;
    phase,
    \* @type: Int -> Set(Str);
    feasible,
    \* @type: Int -> Str;
    fallback,
    \* @type: Int -> Str;
    raw,
    \* @type: Int -> Str;
    chosen,
    \* @type: Int -> Str;
    witness,
    \* @type: Set(Int);
    published

vars == << phase, feasible, fallback, raw, chosen, witness, published >>

Phases == {"idle", "evaluated", "projected", "witnessed", "published"}

TypeOK ==
    /\ DOMAIN phase = CallSet
    /\ DOMAIN feasible = CallSet
    /\ DOMAIN fallback = CallSet
    /\ DOMAIN raw = CallSet
    /\ DOMAIN chosen = CallSet
    /\ DOMAIN witness = CallSet
    /\ published \subseteq CallSet
    /\ \A c \in CallSet :
        /\ phase[c] \in Phases
        /\ feasible[c] \subseteq Outcomes
        /\ fallback[c] \in Outcomes \cup {NoOutcome}
        /\ raw[c] \in Outcomes \cup {NoOutcome}
        /\ chosen[c] \in Outcomes \cup {NoOutcome}
        /\ witness[c] \in Outcomes \cup {NoOutcome}

Init ==
    /\ phase = [c \in CallSet |-> "idle"]
    /\ feasible = [c \in CallSet |-> {}]
    /\ fallback = [c \in CallSet |-> NoOutcome]
    /\ raw = [c \in CallSet |-> NoOutcome]
    /\ chosen = [c \in CallSet |-> NoOutcome]
    /\ witness = [c \in CallSet |-> NoOutcome]
    /\ published = {}

Evaluate(c, f, fb, r) ==
    /\ phase[c] = "idle"
    /\ f /= {}
    /\ fb \in f
    /\ phase' = [phase EXCEPT ![c] = "evaluated"]
    /\ feasible' = [feasible EXCEPT ![c] = f]
    /\ fallback' = [fallback EXCEPT ![c] = fb]
    /\ raw' = [raw EXCEPT ![c] = r]
    /\ UNCHANGED << chosen, witness, published >>

Project(c) ==
    /\ phase[c] = "evaluated"
    /\ chosen' = [chosen EXCEPT ![c] =
          IF raw[c] \in feasible[c] THEN raw[c] ELSE fallback[c]]
    /\ phase' = [phase EXCEPT ![c] = "projected"]
    /\ UNCHANGED << feasible, fallback, raw, witness, published >>

BindWitness(c) ==
    /\ phase[c] = "projected"
    /\ witness' = [witness EXCEPT ![c] = chosen[c]]
    /\ phase' = [phase EXCEPT ![c] = "witnessed"]
    /\ UNCHANGED << feasible, fallback, raw, chosen, published >>

PublishAllow(c) ==
    /\ phase[c] = "witnessed"
    /\ chosen[c] = "allow"
    /\ witness[c] = chosen[c]
    /\ published' = published \cup {c}
    /\ phase' = [phase EXCEPT ![c] = "published"]
    /\ UNCHANGED << feasible, fallback, raw, chosen, witness >>

Stutter ==
    UNCHANGED vars

Next ==
    \/ \E c \in CallSet, f \in SUBSET Outcomes, fb \in Outcomes, r \in Outcomes :
        Evaluate(c, f, fb, r)
    \/ \E c \in CallSet : Project(c)
    \/ \E c \in CallSet : BindWitness(c)
    \/ \E c \in CallSet : PublishAllow(c)
    \/ Stutter

Spec ==
    /\ Init
    /\ [][Next]_vars

ChosenInFeasible ==
    \A c \in CallSet :
        phase[c] \in {"projected", "witnessed", "published"} =>
            chosen[c] \in feasible[c]

WitnessBeforeAllow ==
    \A c \in published :
        /\ chosen[c] = "allow"
        /\ witness[c] = chosen[c]

SafetyInv ==
    /\ TypeOK
    /\ ChosenInFeasible
    /\ WitnessBeforeAllow

=============================================================================
