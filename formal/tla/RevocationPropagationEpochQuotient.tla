---------------- MODULE RevocationPropagationEpochQuotient ----------------
EXTENDS RevocationPropagationPairRefinement

(***************************************************************************)
(* Finite epoch-order quotient for the propagation obligation. Evaluate    *)
(* changes only clock and receipt_log, which the pair projection omits.    *)
(* Removing Evaluate chooses consecutive labels for revocation epochs.     *)
(* Revoke and Propagate are the ORIGINAL full-model actions: no receipt or *)
(* authorization safety claim is made by this reduced check. The argument  *)
(* that arbitrary epoch relabeling preserves order is documented, not a    *)
(* mechanized theorem about unbounded traces.                              *)
(***************************************************************************)

QuotientNext ==
    \/ \E a \in ProcSet, c \in CapSet : Attenuate(a, c)
    \/ \E a \in ProcSet, c \in CapSet : Revoke(a, c)
    \/ PropagateAny

QuotientSpec ==
    /\ Init
    /\ [][QuotientNext]_vars
    /\ WF_vars(PropagateAny)

=============================================================================
