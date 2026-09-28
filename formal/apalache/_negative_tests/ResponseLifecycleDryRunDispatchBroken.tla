---------------- MODULE ResponseLifecycleDryRunDispatchBroken ----------------
(***************************************************************************)
(* A dry-run plan is admitted into live execution and commits recoverable   *)
(* dispatch work. DryRunIsolation must reject it.                           *)
(***************************************************************************)

EXTENDS ResponseLifecycle

=============================================================================
