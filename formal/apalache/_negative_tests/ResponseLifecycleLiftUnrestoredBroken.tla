---------------- MODULE ResponseLifecycleLiftUnrestoredBroken ----------------
(***************************************************************************)
(* Rollback reports a clean lift while an applied contribution remains     *)
(* installed. NoFalseCleanLift must reject it.                              *)
(***************************************************************************)

EXTENDS ResponseLifecycle

=============================================================================
