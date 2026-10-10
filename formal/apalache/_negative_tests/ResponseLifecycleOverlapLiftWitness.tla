---------------- MODULE ResponseLifecycleOverlapLiftWitness ----------------
(***************************************************************************)
(* Rejected-claim witness with unmutated semantics: a lifted plan leaves a  *)
(* target restricted when another plan still holds a contribution on it, so *)
(* the candidate LiftedPlanClearsItsTargets is not in the positive set.      *)
(***************************************************************************)

EXTENDS ResponseLifecycle

=============================================================================
