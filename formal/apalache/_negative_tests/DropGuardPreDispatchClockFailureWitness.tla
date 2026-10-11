----------- MODULE DropGuardPreDispatchClockFailureWitness -----------
(* Rejected availability claim: a failed cancellation-construction clock   *)
(* can leave failed cleanup without a parent append attempt or receipt.   *)
EXTENDS PostAdmissionDropGuard

PreDispatchConstructionFailureUnreachable ==
    \A i \in Invocations :
        ~(parent_construction_failure[i] = "clock" /\ terminal_kind[i] = "fault")

======================================================================
