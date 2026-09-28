---------------- MODULE RevocationPropagationPairLiveness ----------------
(***************************************************************************)
(* Liveness projection of RevocationPropagation onto one ordered authority  *)
(* pair and one capability: the origin's local revocation epoch, the       *)
(* receiver's observed epoch, and the epochs still in flight from origin   *)
(* to receiver. Every full-model step that touches other pairs or          *)
(* capabilities projects to a stutter; RevocationPropagationPairRefinement *)
(* checks that projection against the full transition relation.            *)
(*                                                                          *)
(* The full model's liveness premise is WF_vars(PropagateAny) over one     *)
(* shared pending set. The pair projection cannot see other pairs'         *)
(* messages, so it states the transferred premise directly: whenever the   *)
(* receiver lags the origin, the receiver eventually observes a newer      *)
(* epoch. PendingCoversLag in the refinement module is the bounded safety  *)
(* fact behind that transfer: a lag always has an in-flight message for    *)
(* the receiver carrying the lagging epoch, and weak fairness of           *)
(* propagation drains every in-flight message because revocations are      *)
(* finite. The transfer itself is an argument recorded with the claim, not *)
(* a checked theorem.                                                       *)
(*                                                                          *)
(* Apalache 0.50.1 does not encode WF or ENABLED in temporal properties, so *)
(* ObserveWeakFair expands weak fairness into primitive temporal logic with *)
(* exact state-derived enabledness, as the distributed projection does.    *)
(***************************************************************************)

EXTENDS Naturals, FiniteSets

CONSTANTS
    \* @type: Int;
    EpochMax

Epochs == 1..EpochMax

ASSUME EpochMax >= 1

VARIABLES
    \* @type: Int;
    originEpoch,
    \* @type: Int;
    observedEpoch,
    \* @type: Set(Int);
    pendingEpochs

vars == <<originEpoch, observedEpoch, pendingEpochs>>

Max2(x, y) == IF x >= y THEN x ELSE y

Init ==
    /\ originEpoch = 0
    /\ observedEpoch = 0
    /\ pendingEpochs = {}

\* The origin revokes locally. Its epoch is the full model's clock, which is
\* above every epoch the pair has seen, and exactly one propagation message
\* to the receiver enters flight. A revoked authority never revokes again.
RevokeLocal(e) ==
    /\ e \in Epochs
    /\ originEpoch = 0
    /\ e > observedEpoch
    /\ originEpoch' = e
    /\ pendingEpochs' = {e}
    /\ UNCHANGED observedEpoch

\* The origin installs a newer epoch propagated by a third authority. That
\* authority broadcast the same epoch to the receiver on its own channel.
AbsorbRemote(e) ==
    /\ e \in Epochs
    /\ e > originEpoch
    /\ originEpoch' = e
    /\ UNCHANGED <<observedEpoch, pendingEpochs>>

\* One in-flight message from the origin reaches the receiver, which keeps
\* the higher of its view and the delivered epoch.
Deliver(e) ==
    /\ e \in pendingEpochs
    /\ pendingEpochs' = pendingEpochs \ {e}
    /\ observedEpoch' = Max2(observedEpoch, e)
    /\ UNCHANGED originEpoch

\* The receiver observes a newer epoch from its own revocation or from a
\* third authority's message.
ObserveOther(e) ==
    /\ e \in Epochs
    /\ e > observedEpoch
    /\ observedEpoch' = e
    /\ UNCHANGED <<originEpoch, pendingEpochs>>

Stutter == UNCHANGED vars

Next ==
    \/ \E e \in Epochs : RevokeLocal(e)
    \/ \E e \in Epochs : AbsorbRemote(e)
    \/ \E e \in Epochs : Deliver(e)
    \/ \E e \in Epochs : ObserveOther(e)
    \/ Stutter

Spec ==
    /\ Init
    /\ [][Next]_vars

PairRevocationObserved == originEpoch # 0

PairCaughtUp == observedEpoch >= originEpoch

ObserveEnabled == originEpoch > observedEpoch

ObserveProgressAction == observedEpoch' > observedEpoch

ObserveWeakFair ==
    \/ []<>(~ObserveEnabled)
    \/ []<><<ObserveProgressAction>>_observedEpoch

RevocationEventuallySeenPair ==
    ObserveWeakFair => (PairRevocationObserved ~> PairCaughtUp)

=============================================================================
