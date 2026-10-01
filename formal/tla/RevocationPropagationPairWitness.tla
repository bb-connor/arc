--------------- MODULE RevocationPropagationPairWitness ---------------
(***************************************************************************)
(* Executable non-vacuity witness for the pair liveness projection. The    *)
(* final state has delivered the origin's revocation and can stutter       *)
(* forever with the weak-fairness enabledness predicate false.             *)
(***************************************************************************)

EXTENDS RevocationPropagationPairLiveness

VARIABLES
    \* @type: Int;
    phase

witnessVars == <<originEpoch, observedEpoch, pendingEpochs, phase>>

WitnessInit ==
    /\ Init
    /\ phase = 0

WitnessNext ==
    \/ /\ phase = 0
       /\ RevokeLocal(1)
       /\ phase' = 1
    \/ /\ phase = 1
       /\ Deliver(1)
       /\ phase' = 2
    \/ /\ phase = 2
       /\ Stutter
       /\ UNCHANGED phase

WitnessSpec ==
    /\ WitnessInit
    /\ [][WitnessNext]_witnessVars

FairObservationWitness ==
    \/ phase < 2
    \/ /\ phase = 2
       /\ PairRevocationObserved
       /\ PairCaughtUp
       /\ pendingEpochs = {}
       /\ ~ObserveEnabled

=============================================================================
