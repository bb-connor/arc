----------- MODULE DropGuardPostDispatchClockFailureWitness ----------
(* Rejected availability claim: unavailable trusted time can stop parent  *)
(* cancellation construction after dispatch. Resources remain retained.   *)
EXTENDS PostAdmissionDropGuard

PostDispatchConstructionFailureUnreachable ==
    \A i \in Invocations :
        ~(parent_construction_failure[i] = "clock" /\ terminal_kind[i] = "cancel")

======================================================================
