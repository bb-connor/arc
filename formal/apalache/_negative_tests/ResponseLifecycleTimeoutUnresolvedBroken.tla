---------------- MODULE ResponseLifecycleTimeoutUnresolvedBroken ----------------
(***************************************************************************)
(* The applying lease deadline closes the response while an issued effect  *)
(* is still unresolved, so a later landing installs a contribution behind a *)
(* failed receipt. ReceiptStateTruthful must reject it.                     *)
(***************************************************************************)

EXTENDS ResponseLifecycle

=============================================================================
