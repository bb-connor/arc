---------------- MODULE ResponseLifecycleClearOnRemoveBroken ----------------
(***************************************************************************)
(* Removing one plan contribution clears the whole target restriction even *)
(* though another plan still holds a contribution there. OverlapPreserved   *)
(* must reject it.                                                          *)
(***************************************************************************)

EXTENDS ResponseLifecycle

=============================================================================
