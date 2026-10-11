-------------- MODULE RevocationPropagationPairRefinement --------------
(***************************************************************************)
(* Bounded refinement from the full RevocationPropagation relation to the  *)
(* pair projection, and the safety fact that transfers its fairness.       *)
(*                                                                          *)
(* Every full-model step projects to a pair step or a pair stutter: the    *)
(* selected origin's Revoke is RevokeLocal, a propagation installed at the *)
(* origin is AbsorbRemote, a propagation from the origin to the receiver is *)
(* Deliver, any other epoch installed at the receiver is ObserveOther, and *)
(* attenuation, evaluation and unrelated pairs stutter.                     *)
(*                                                                          *)
(* PendingCoversLag: whenever one authority's epoch for a capability is    *)
(* ahead of another's, the pending set still holds a message to the        *)
(* lagging authority carrying at least the leading epoch. Under            *)
(* WF_vars(PropagateAny) every pending message is eventually consumed,     *)
(* because each Revoke fires at most once per authority and capability, so *)
(* the lag closes. This is what the pair projection's ObserveWeakFair      *)
(* premise stands for.                                                      *)
(***************************************************************************)

EXTENDS RevocationPropagation

CONSTANTS
    \* @type: Int;
    SelectedOrigin,
    \* @type: Int;
    SelectedReceiver,
    \* @type: Int;
    SelectedCapability,
    \* @type: Int;
    EpochBound

ASSUME
    /\ SelectedOrigin \in ProcSet
    /\ SelectedReceiver \in ProcSet
    /\ SelectedOrigin # SelectedReceiver
    /\ SelectedCapability \in CapSet
    /\ EpochBound >= 1

PairPending ==
    { m \in pending :
        /\ m.from = SelectedOrigin
        /\ m.to = SelectedReceiver
        /\ m.cap = SelectedCapability }

Scalar == INSTANCE RevocationPropagationPairLiveness
    WITH EpochMax <- EpochBound,
         originEpoch <- rev_epoch[SelectedOrigin][SelectedCapability],
         observedEpoch <- rev_epoch[SelectedReceiver][SelectedCapability],
         pendingEpochs <- { m.epoch : m \in PairPending }

TemporalProjectionRefines == Scalar!Spec

PendingCoversLag ==
    \A a \in ProcSet, b \in ProcSet, c \in CapSet :
        rev_epoch[a][c] > rev_epoch[b][c] =>
            \E m \in pending :
                /\ m.to = b
                /\ m.cap = c
                /\ m.epoch >= rev_epoch[a][c]

=============================================================================
