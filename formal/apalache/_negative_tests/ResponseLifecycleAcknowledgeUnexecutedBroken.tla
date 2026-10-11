---------------- MODULE ResponseLifecycleAcknowledgeUnexecutedBroken ----------------
(***************************************************************************)
(* The owner acknowledges an effect as applied before the effect journal   *)
(* records any outcome. ReceiptStateTruthful must reject it.               *)
(***************************************************************************)

EXTENDS ResponseLifecycle

=============================================================================
