---------------- MODULE ResponseLifecycleActivateUnacknowledgedBroken ----------------
(***************************************************************************)
(* The response reports Active while an effect is still only requested.    *)
(* ReceiptStateTruthful must reject it.                                     *)
(***************************************************************************)

EXTENDS ResponseLifecycle

=============================================================================
