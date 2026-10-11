---------------- MODULE ResponseLifecycleGuessNotExecutedBroken ----------------
(***************************************************************************)
(* A takeover records an effect as not executed without reading the effect *)
(* journal, while the in-flight request can still land. ReceiptStateTruthful *)
(* must reject it.                                                          *)
(***************************************************************************)

EXTENDS ResponseLifecycle

=============================================================================
