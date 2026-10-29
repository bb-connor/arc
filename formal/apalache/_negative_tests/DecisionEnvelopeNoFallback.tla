--------------------- MODULE DecisionEnvelopeNoFallback ---------------------
(***************************************************************************)
(* DELIBERATELY BROKEN variant of DecisionEnvelope. ProjectNoFallback      *)
(* returns the raw outcome even when the envelope does not admit it.      *)
(* Apalache MUST find a counterexample to ChosenInFeasible. If it reports *)
(* NoError, the property is unsound.                                      *)
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

\* BROKEN: the fallback branch is removed.
ProjectNoFallback(c) ==
    /\ phase[c] = "evaluated"
    /\ chosen' = [chosen EXCEPT ![c] = raw[c]]
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
    \/ \E c \in CallSet : ProjectNoFallback(c)
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
