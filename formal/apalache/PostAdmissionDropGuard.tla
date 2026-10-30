---------------------- MODULE PostAdmissionDropGuard ----------------------
(***************************************************************************)
(* Bounded lifecycle model: two invocations with at most one child each.  *)
(* Invocation 1 explores all local admission and cleanup profiles.        *)
(* Invocation 2 uses the maximal non-monetary dispatch-to-drop profile.   *)
(*                                                                        *)
(* Child append succeeds before the terminal transition credits children. *)
(* Parent acknowledgement and durable presence are separate model facts.  *)
(* A known returned output reaches reconciliation and commits its hold.   *)
(* Post-dispatch errors, including URL elicitation, are outcome-unknown.  *)
(* Cleanup before the effect boundary is reversible.                      *)
(*                                                                        *)
(* The modeled resources are holds, invocation slots, leases and children.*)
(* The invocation slot is an admission budget. Evidence capacity and      *)
(* payment-rail authorization are outside the resource model.             *)
(*                                                                        *)
(* Buffered evidence and durable-saga handoff transfer custody.           *)
(* Receipt persistence requires an acknowledged owning append.            *)
(* PreparedResponse contains signed work awaiting that acknowledgement.   *)
(*                                                                        *)
(* The model omits ambiguous child writes, write barriers, identity readback,*)
(* retries after established absence, and retained reconciliation failures.*)
(* Its invariants do not establish Rust ownership refinement, logical     *)
(* terminal uniqueness under retries, eventual persistence, recovery      *)
(* liveness, worker shutdown or crash recovery.                           *)
(* Callback failure, credential-store atomicity, SQL recovery, cryptography*)
(* and signed expiry are outside the model.                               *)
(*                                                                        *)
(* Implementation anchors:                                                *)
(*   cleanup: PostAdmissionDropGuard::handle_pre_dispatch_drop;           *)
(*   effect boundary: PostEffectObligation::enter;                        *)
(*   receipt binding: DischargeBinding::validate_receipt;                 *)
(*   child publication: effect_obligation/post_effect.rs::flush_children;             *)
(*   return custody: prepare_ordinary and record_durable_return;          *)
(*   parent commit: commit_terminal_receipt;                              *)
(*   delivery: Discharged::deliver and PreparedResponse::finish_delivery; *)
(*   failure custody: PostEffectObligation::fail, buffer and drop;        *)
(*   recovery: EvidenceRecoveryResources and EvidenceRecovery::ensure_clear.*)
(***************************************************************************)

EXTENDS Naturals, FiniteSets

(***************************************************************************)
(* Reservation law (normative text in chio-kernel/src/budget_store.rs):    *)
(* 1. Partition: reserved amount equals committed plus released plus        *)
(*    retained plus outstanding at every reachable state, and outstanding  *)
(*    is nonnegative.                                                       *)
(* 2. Terminal uniqueness: a terminal admission has no outstanding amount  *)
(*    and exactly one terminal classification.                             *)
(* 3. Child splits: admitted sibling shares never exceed the parent share, *)
(*    and every child independently obeys clauses 1 and 2.                 *)
(*                                                                         *)
(* Equivalent checks are maintained in                                     *)
(* chio-kernel-core/src/formal_aeneas.rs and                               *)
(* chio-kernel/tests/property_reservation_ledger.rs.                        *)
(***************************************************************************)

CONSTANTS
    \* @type: Set(Int);
    Invocations,
    \* @type: Int;
    ChildMax,
    \* @type: Str;
    Mutation

Resources == {"hold", "slot", "lease", "child"}
BudgetMax == 4
AdmissionProfiles == {
    {},
    {"lease"},
    {"child"},
    {"lease", "child"},
    {"hold"},
    {"slot"},
    {"hold", "lease"},
    {"slot", "lease"},
    {"hold", "child"},
    {"slot", "child"},
    {"hold", "lease", "child"},
    {"slot", "lease", "child"}
}
CleanupFailureProfiles == AdmissionProfiles
AdmissionProfilesFor(i) ==
    IF i = 1
    THEN AdmissionProfiles
    ELSE {{"slot", "lease", "child"}}

Phases == {
    "idle",
    "admitted",
    "dispatch_started",
    "streaming",
    "terminal_ok",
    "terminal_denied",
    "terminal_unwound",
    "terminal_fault"
}
TerminalKinds == {"none", "allow", "deny", "incomplete", "cancel", "fault", "unwound"}
ParentReceiptKinds == {"allow", "deny", "incomplete", "cancel", "fault"}
ParentAppendStates == {"not-attempted", "construction-failed", "outcome-unknown", "committed"}
ServerErrorKinds == {"deny", "incomplete", "cancel", "url"}
RecordedServerErrorKinds == ServerErrorKinds \cup {"none"}
Mutations == {
    "none",
    "discard-child-buffer",
    "skip-child-release",
    "skip-slot-release",
    "omit-fault-receipt",
    "release-incomplete-lease",
    "skip-deny-retention",
    "release-post-dispatch-state",
    "skip-child-capacity-guard"
}

ASSUME
    /\ Invocations = 1..2
    /\ ChildMax = 1
    /\ Mutation \in Mutations

VARIABLES
    \* @type: Int -> Str;
    phase,
    \* @type: Int -> (Str -> Str);
    ledger,
    \* @type: Int -> Set(Str);
    admitted_resources,
    \* @type: Int -> Set(Str);
    unwind_failed,
    \* @type: Int -> Int;
    child_buf,
    \* @type: Int -> Int;
    child_total,
    \* @type: Int -> Int;
    child_logged,
    \* @type: Int -> Int;
    parent_receipts,
    \* @type: Int -> Int;
    parent_append_attempts,
    \* @type: Int -> Str;
    parent_append_state,
    \* @type: Int -> Str;
    parent_construction_failure,
    \* @type: Int -> Str;
    parent_kind_logged,
    \* @type: Int -> Bool;
    children_before_parent,
    \* @type: Int -> Bool;
    post_dispatch_outcome_unknown,
    \* @type: Int -> Str;
    server_error_kind,
    \* @type: Int -> Bool;
    nested_bridge_active_at_error,
    \* @type: Int -> Str;
    terminal_kind

vars == <<
    phase,
    ledger,
    admitted_resources,
    unwind_failed,
    child_buf,
    child_total,
    child_logged,
    parent_receipts,
    parent_append_attempts,
    parent_append_state,
    parent_construction_failure,
    parent_kind_logged,
    children_before_parent,
    post_dispatch_outcome_unknown,
    server_error_kind,
    nested_bridge_active_at_error,
    terminal_kind
>>

CleanupFailureSets(i) ==
    IF i = 1
    THEN CleanupFailureProfiles
    ELSE {{}}

ParentAppendOutcomes(i) ==
    IF i = 1
    THEN {"outcome-unknown", "committed"}
    ELSE {"committed"}

ParentPersistenceOutcomes(append_outcome) ==
    IF append_outcome = "committed"
    THEN {TRUE}
    ELSE BOOLEAN

ServerErrorReceiptKind(error_kind) ==
    IF error_kind = "url" THEN "incomplete" ELSE error_kind

IsTerminal(i) == phase[i] \in {
    "terminal_ok",
    "terminal_denied",
    "terminal_unwound",
    "terminal_fault"
}

StatusAmount(i, status) ==
    Cardinality({resource \in admitted_resources[i] : ledger[i][resource] = status})

ReservedAmount(i) == Cardinality(admitted_resources[i])

CountedLedger(i) == [
    outstanding |-> StatusAmount(i, "reserved"),
    committed |-> StatusAmount(i, "committed"),
    released |-> StatusAmount(i, "released"),
    retained |-> StatusAmount(i, "retained")
]

CountedLedgerDomains ==
    \A i \in Invocations :
        /\ ReservedAmount(i) \in 0..BudgetMax
        /\ CountedLedger(i).outstanding \in 0..BudgetMax
        /\ CountedLedger(i).committed \in 0..BudgetMax
        /\ CountedLedger(i).released \in 0..BudgetMax
        /\ CountedLedger(i).retained \in 0..BudgetMax

PartitionAtEveryState ==
    \A i \in Invocations :
        ReservedAmount(i) =
            CountedLedger(i).committed
            + CountedLedger(i).released
            + CountedLedger(i).retained
            + CountedLedger(i).outstanding

ActiveChildShares ==
    Cardinality({i \in Invocations :
        /\ "child" \in admitted_resources[i]
        /\ ledger[i]["child"] \notin {"none", "released"}})

ChildSplitsBounded == ActiveChildShares <= ChildMax

ResolveAll(current, disposition) ==
    [resource \in Resources |->
        IF current[resource] = "reserved"
        THEN disposition
        ELSE current[resource]]

ResolveReturnedOutput(current, kind) ==
    [resource \in Resources |->
        IF current[resource] # "reserved"
        THEN current[resource]
        ELSE IF resource = "lease"
        THEN
            IF /\ kind = "incomplete"
               /\ Mutation = "release-incomplete-lease"
            THEN "released"
            ELSE IF /\ kind = "deny"
                    /\ Mutation = "skip-deny-retention"
            THEN "reserved"
            ELSE "retained"
        ELSE "committed"]

ResolvePreDispatch(current, failed) ==
    [resource \in Resources |->
        IF current[resource] # "reserved"
        THEN current[resource]
        ELSE IF resource \in failed
        THEN "retained"
        ELSE IF /\ resource = "child"
                /\ Mutation = "skip-child-release"
        THEN "reserved"
        ELSE IF /\ resource = "slot"
                /\ Mutation = "skip-slot-release"
        THEN "reserved"
        ELSE "released"]

ResolvePostDispatch(current) ==
    [resource \in Resources |->
        IF current[resource] # "reserved"
        THEN current[resource]
        ELSE IF resource \in {"lease", "hold"}
        THEN
            IF Mutation = "release-post-dispatch-state"
            THEN "released"
            ELSE "retained"
        ELSE "committed"]

DomainsOK ==
    /\ Mutation \in Mutations
    /\ \A i \in Invocations :
        /\ phase[i] \in Phases
        /\ admitted_resources[i] \subseteq Resources
        /\ unwind_failed[i] \subseteq admitted_resources[i]
        /\ child_buf[i] \in 0..ChildMax
        /\ child_total[i] \in 0..ChildMax
        /\ child_buf[i] <= child_total[i]
        /\ child_logged[i] \in 0..ChildMax
        /\ child_logged[i] <= child_total[i]
        /\ parent_receipts[i] \in 0..1
        /\ parent_append_attempts[i] \in 0..1
        /\ parent_append_state[i] \in ParentAppendStates
        /\ parent_construction_failure[i] \in {"none", "clock"}
        /\ parent_kind_logged[i] \in TerminalKinds
        /\ children_before_parent[i] \in BOOLEAN
        /\ post_dispatch_outcome_unknown[i] \in BOOLEAN
        /\ server_error_kind[i] \in RecordedServerErrorKinds
        /\ nested_bridge_active_at_error[i] \in BOOLEAN
        /\ terminal_kind[i] \in TerminalKinds

Init ==
    /\ phase = [i \in Invocations |-> "idle"]
    /\ ledger = [i \in Invocations |-> [resource \in Resources |-> "none"]]
    /\ admitted_resources = [i \in Invocations |-> {}]
    /\ unwind_failed = [i \in Invocations |-> {}]
    /\ child_buf = [i \in Invocations |-> 0]
    /\ child_total = [i \in Invocations |-> 0]
    /\ child_logged = [i \in Invocations |-> 0]
    /\ parent_receipts = [i \in Invocations |-> 0]
    /\ parent_append_attempts = [i \in Invocations |-> 0]
    /\ parent_append_state = [i \in Invocations |-> "not-attempted"]
    /\ parent_construction_failure = [i \in Invocations |-> "none"]
    /\ parent_kind_logged = [i \in Invocations |-> "none"]
    /\ children_before_parent = [i \in Invocations |-> TRUE]
    /\ post_dispatch_outcome_unknown = [i \in Invocations |-> FALSE]
    /\ server_error_kind = [i \in Invocations |-> "none"]
    /\ nested_bridge_active_at_error = [i \in Invocations |-> FALSE]
    /\ terminal_kind = [i \in Invocations |-> "none"]

Admit(i) ==
    /\ phase[i] = "idle"
    /\ \E resources \in AdmissionProfilesFor(i) :
        /\ IF "child" \in resources
           THEN \/ ActiveChildShares < ChildMax
                \/ Mutation = "skip-child-capacity-guard"
           ELSE TRUE
        /\ phase' = [phase EXCEPT ![i] = "admitted"]
        /\ ledger' = [ledger EXCEPT ![i] =
            [resource \in Resources |->
                IF resource \in resources THEN "reserved" ELSE "none"]]
        /\ admitted_resources' = [admitted_resources EXCEPT ![i] = resources]
        /\ unwind_failed' = [unwind_failed EXCEPT ![i] = {}]
        /\ child_buf' = [child_buf EXCEPT ![i] = 0]
        /\ child_total' = [child_total EXCEPT ![i] = 0]
        /\ child_logged' = [child_logged EXCEPT ![i] = 0]
        /\ parent_receipts' = [parent_receipts EXCEPT ![i] = 0]
        /\ parent_append_attempts' = [parent_append_attempts EXCEPT ![i] = 0]
        /\ parent_append_state' = [parent_append_state EXCEPT ![i] = "not-attempted"]
        /\ parent_kind_logged' = [parent_kind_logged EXCEPT ![i] = "none"]
        /\ children_before_parent' = [children_before_parent EXCEPT ![i] = TRUE]
        /\ post_dispatch_outcome_unknown' =
            [post_dispatch_outcome_unknown EXCEPT ![i] = FALSE]
        /\ server_error_kind' = [server_error_kind EXCEPT ![i] = "none"]
        /\ nested_bridge_active_at_error' =
            [nested_bridge_active_at_error EXCEPT ![i] = FALSE]
        /\ terminal_kind' = [terminal_kind EXCEPT ![i] = "none"]

StartDispatch(i) ==
    /\ phase[i] = "admitted"
    /\ phase' = [phase EXCEPT ![i] = "dispatch_started"]
    /\ UNCHANGED << ledger, admitted_resources, unwind_failed, child_buf,
                     child_total, child_logged, parent_receipts,
                     parent_append_attempts, parent_append_state,
                     parent_kind_logged, children_before_parent,
                     post_dispatch_outcome_unknown, server_error_kind,
                     nested_bridge_active_at_error, terminal_kind >>

StreamChunk(i) ==
    /\ phase[i] \in {"dispatch_started", "streaming"}
    /\ child_buf[i] < ChildMax
    /\ phase' = [phase EXCEPT ![i] = "streaming"]
    /\ child_buf' = [child_buf EXCEPT ![i] = @ + 1]
    /\ child_total' = [child_total EXCEPT ![i] = @ + 1]
    /\ UNCHANGED << ledger, admitted_resources, unwind_failed, child_logged,
                     parent_receipts, parent_append_attempts,
                     parent_append_state, parent_kind_logged,
                     children_before_parent, post_dispatch_outcome_unknown,
                     server_error_kind, nested_bridge_active_at_error,
                     terminal_kind >>

CompleteOk(i) ==
    /\ i = 1
    /\ phase[i] \in {"dispatch_started", "streaming"}
    /\ parent_append_state[i] = "not-attempted"
    /\ \E append_outcome \in ParentAppendOutcomes(i) :
        /\ \E append_persisted \in ParentPersistenceOutcomes(append_outcome) :
            /\ phase' = [phase EXCEPT ![i] = "terminal_ok"]
            /\ ledger' = [ledger EXCEPT ![i] = ResolveAll(@, "committed")]
            /\ child_buf' = [child_buf EXCEPT ![i] = 0]
            /\ child_logged' = [child_logged EXCEPT ![i] = @ + child_buf[i]]
            /\ parent_append_attempts' = [parent_append_attempts EXCEPT ![i] = @ + 1]
            /\ parent_append_state' = [parent_append_state EXCEPT ![i] = append_outcome]
            /\ parent_receipts' = [parent_receipts EXCEPT ![i] =
                @ + IF append_persisted THEN 1 ELSE 0]
            /\ parent_kind_logged' = [parent_kind_logged EXCEPT ![i] =
                IF append_persisted THEN "allow" ELSE "none"]
            /\ children_before_parent' = [children_before_parent EXCEPT ![i] =
                child_logged[i] + child_buf[i] = child_total[i]]
            /\ terminal_kind' = [terminal_kind EXCEPT ![i] = "allow"]
            /\ UNCHANGED << admitted_resources, unwind_failed, child_total,
                             post_dispatch_outcome_unknown, server_error_kind,
                             nested_bridge_active_at_error >>

DenyPostInvocation(i) ==
    /\ i = 1
    /\ phase[i] \in {"dispatch_started", "streaming"}
    /\ parent_append_state[i] = "not-attempted"
    /\ \E append_outcome \in ParentAppendOutcomes(i) :
        /\ \E append_persisted \in ParentPersistenceOutcomes(append_outcome) :
            /\ phase' = [phase EXCEPT ![i] = "terminal_denied"]
            /\ ledger' = [ledger EXCEPT ![i] =
                ResolveReturnedOutput(@, "deny")]
            /\ child_buf' = [child_buf EXCEPT ![i] = 0]
            /\ child_logged' = [child_logged EXCEPT ![i] = @ + child_buf[i]]
            /\ parent_append_attempts' = [parent_append_attempts EXCEPT ![i] = @ + 1]
            /\ parent_append_state' = [parent_append_state EXCEPT ![i] = append_outcome]
            /\ parent_receipts' = [parent_receipts EXCEPT ![i] =
                @ + IF append_persisted THEN 1 ELSE 0]
            /\ parent_kind_logged' = [parent_kind_logged EXCEPT ![i] =
                IF append_persisted THEN "deny" ELSE "none"]
            /\ children_before_parent' = [children_before_parent EXCEPT ![i] =
                child_logged[i] + child_buf[i] = child_total[i]]
            /\ terminal_kind' = [terminal_kind EXCEPT ![i] = "deny"]
            /\ UNCHANGED << admitted_resources, unwind_failed, child_total,
                             post_dispatch_outcome_unknown, server_error_kind,
                             nested_bridge_active_at_error >>

IncompleteStream(i) ==
    /\ i = 1
    /\ phase[i] \in {"dispatch_started", "streaming"}
    /\ parent_append_state[i] = "not-attempted"
    /\ \E append_outcome \in ParentAppendOutcomes(i) :
        /\ \E append_persisted \in ParentPersistenceOutcomes(append_outcome) :
            /\ phase' = [phase EXCEPT ![i] = "terminal_denied"]
            /\ ledger' = [ledger EXCEPT ![i] =
                ResolveReturnedOutput(@, "incomplete")]
            /\ child_buf' = [child_buf EXCEPT ![i] = 0]
            /\ child_logged' = [child_logged EXCEPT ![i] = @ + child_buf[i]]
            /\ parent_append_attempts' = [parent_append_attempts EXCEPT ![i] = @ + 1]
            /\ parent_append_state' = [parent_append_state EXCEPT ![i] = append_outcome]
            /\ parent_receipts' = [parent_receipts EXCEPT ![i] =
                @ + IF append_persisted THEN 1 ELSE 0]
            /\ parent_kind_logged' = [parent_kind_logged EXCEPT ![i] =
                IF append_persisted THEN "incomplete" ELSE "none"]
            /\ children_before_parent' = [children_before_parent EXCEPT ![i] =
                child_logged[i] + child_buf[i] = child_total[i]]
            /\ terminal_kind' = [terminal_kind EXCEPT ![i] = "incomplete"]
            /\ UNCHANGED << admitted_resources, unwind_failed, child_total,
                             post_dispatch_outcome_unknown, server_error_kind,
                             nested_bridge_active_at_error >>

ServerErrorPostDispatch(i) ==
    /\ i = 1
    /\ phase[i] \in {"dispatch_started", "streaming"}
    /\ parent_append_state[i] = "not-attempted"
    /\ \E error_kind \in ServerErrorKinds :
        /\ \E nested_bridge_active \in BOOLEAN :
            /\ \E append_outcome \in ParentAppendOutcomes(i) :
                /\ \E append_persisted \in ParentPersistenceOutcomes(append_outcome) :
                    LET receipt_kind == ServerErrorReceiptKind(error_kind)
                    IN
                    /\ phase' = [phase EXCEPT ![i] =
                        IF receipt_kind = "cancel"
                        THEN "terminal_fault"
                        ELSE "terminal_denied"]
                    /\ ledger' = [ledger EXCEPT ![i] = ResolvePostDispatch(@)]
                    /\ child_buf' = [child_buf EXCEPT ![i] = 0]
                    /\ child_logged' =
                        [child_logged EXCEPT ![i] = @ + child_buf[i]]
                    /\ parent_append_attempts' =
                        [parent_append_attempts EXCEPT ![i] = @ + 1]
                    /\ parent_append_state' =
                        [parent_append_state EXCEPT ![i] = append_outcome]
                    /\ parent_receipts' = [parent_receipts EXCEPT ![i] =
                        @ + IF append_persisted THEN 1 ELSE 0]
                    /\ parent_kind_logged' = [parent_kind_logged EXCEPT ![i] =
                        IF append_persisted THEN receipt_kind ELSE "none"]
                    /\ children_before_parent' =
                        [children_before_parent EXCEPT ![i] =
                            child_logged[i] + child_buf[i] = child_total[i]]
                    /\ post_dispatch_outcome_unknown' =
                        [post_dispatch_outcome_unknown EXCEPT ![i] = TRUE]
                    /\ server_error_kind' =
                        [server_error_kind EXCEPT ![i] = error_kind]
                    /\ nested_bridge_active_at_error' =
                        [nested_bridge_active_at_error EXCEPT
                            ![i] = nested_bridge_active]
                    /\ terminal_kind' =
                        [terminal_kind EXCEPT ![i] = receipt_kind]
                    /\ UNCHANGED << admitted_resources, unwind_failed,
                                     child_total >>

DropPreDispatch(i) ==
    /\ i = 1
    /\ phase[i] = "admitted"
    /\ \E failed \in CleanupFailureSets(i) :
        /\ failed \subseteq admitted_resources[i]
        /\ ledger' = [ledger EXCEPT ![i] = ResolvePreDispatch(@, failed)]
        /\ unwind_failed' = [unwind_failed EXCEPT ![i] = failed]
        /\ IF failed = {}
           THEN
                /\ phase' = [phase EXCEPT ![i] = "terminal_unwound"]
                /\ terminal_kind' = [terminal_kind EXCEPT ![i] = "unwound"]
                /\ UNCHANGED << parent_receipts, parent_append_attempts,
                                 parent_append_state, parent_kind_logged >>
           ELSE
                /\ phase' = [phase EXCEPT ![i] = "terminal_fault"]
                /\ terminal_kind' = [terminal_kind EXCEPT ![i] = "fault"]
                /\ IF Mutation = "omit-fault-receipt"
                   THEN UNCHANGED << parent_receipts, parent_append_attempts,
                                    parent_append_state, parent_kind_logged >>
                   ELSE
                        /\ parent_append_state[i] = "not-attempted"
                        /\ \E append_outcome \in ParentAppendOutcomes(i) :
                            /\ \E append_persisted \in ParentPersistenceOutcomes(append_outcome) :
                                /\ parent_append_attempts' = [parent_append_attempts EXCEPT ![i] = @ + 1]
                                /\ parent_append_state' = [parent_append_state EXCEPT ![i] = append_outcome]
                                /\ parent_receipts' = [parent_receipts EXCEPT ![i] =
                                    @ + IF append_persisted THEN 1 ELSE 0]
                                /\ parent_kind_logged' = [parent_kind_logged EXCEPT ![i] =
                                    IF append_persisted THEN "fault" ELSE "none"]
        /\ UNCHANGED << admitted_resources, child_buf, child_total,
                         child_logged, children_before_parent,
                         post_dispatch_outcome_unknown, server_error_kind,
                         nested_bridge_active_at_error >>

DropPostDispatch(i) ==
    /\ phase[i] \in {"dispatch_started", "streaming"}
    /\ parent_append_state[i] = "not-attempted"
    /\ \E append_outcome \in ParentAppendOutcomes(i) :
        /\ \E append_persisted \in ParentPersistenceOutcomes(append_outcome) :
            LET flushed_count ==
                    IF Mutation = "discard-child-buffer"
                    THEN child_logged[i]
                    ELSE child_logged[i] + child_buf[i]
            IN
            /\ phase' = [phase EXCEPT ![i] = "terminal_fault"]
            /\ ledger' = [ledger EXCEPT ![i] = ResolvePostDispatch(@)]
            /\ child_buf' = [child_buf EXCEPT ![i] = 0]
            /\ child_logged' = [child_logged EXCEPT ![i] = flushed_count]
            /\ parent_append_attempts' = [parent_append_attempts EXCEPT ![i] = @ + 1]
            /\ parent_append_state' = [parent_append_state EXCEPT ![i] = append_outcome]
            /\ parent_receipts' = [parent_receipts EXCEPT ![i] =
                @ + IF append_persisted THEN 1 ELSE 0]
            /\ parent_kind_logged' = [parent_kind_logged EXCEPT ![i] =
                IF append_persisted THEN "cancel" ELSE "none"]
            /\ children_before_parent' = [children_before_parent EXCEPT ![i] =
                flushed_count = child_total[i]]
            /\ post_dispatch_outcome_unknown' =
                [post_dispatch_outcome_unknown EXCEPT ![i] = TRUE]
            /\ terminal_kind' = [terminal_kind EXCEPT ![i] = "cancel"]
            /\ UNCHANGED << admitted_resources, unwind_failed, child_total,
                             server_error_kind,
                             nested_bridge_active_at_error >>

(* These separate events represent a failed trusted clock read before the    *)
(* cancellation builder is invoked. They never stand in for a successful     *)
(* construction with an omitted append, or for an outcome-unknown append.    *)
DropPreDispatchConstructionFailed(i) ==
    /\ i = 1
    /\ phase[i] = "admitted"
    /\ parent_append_state[i] = "not-attempted"
    /\ \E failed \in CleanupFailureSets(i) :
        /\ failed # {}
        /\ failed \subseteq admitted_resources[i]
        /\ ledger' = [ledger EXCEPT ![i] = ResolvePreDispatch(@, failed)]
        /\ unwind_failed' = [unwind_failed EXCEPT ![i] = failed]
    /\ phase' = [phase EXCEPT ![i] = "terminal_fault"]
    /\ terminal_kind' = [terminal_kind EXCEPT ![i] = "fault"]
    /\ parent_append_state' = [parent_append_state EXCEPT ![i] = "construction-failed"]
    /\ parent_construction_failure' = [parent_construction_failure EXCEPT ![i] = "clock"]
    /\ UNCHANGED << admitted_resources, child_buf, child_total, child_logged,
                     parent_append_attempts, parent_receipts, parent_kind_logged,
                     children_before_parent, post_dispatch_outcome_unknown,
                     server_error_kind, nested_bridge_active_at_error >>

DropPostDispatchConstructionFailed(i) ==
    /\ phase[i] \in {"dispatch_started", "streaming"}
    /\ parent_append_state[i] = "not-attempted"
    /\ LET flushed_count ==
               IF Mutation = "discard-child-buffer"
               THEN child_logged[i]
               ELSE child_logged[i] + child_buf[i]
       IN
        /\ phase' = [phase EXCEPT ![i] = "terminal_fault"]
        /\ ledger' = [ledger EXCEPT ![i] = ResolvePostDispatch(@)]
        /\ child_buf' = [child_buf EXCEPT ![i] = 0]
        /\ child_logged' = [child_logged EXCEPT ![i] = flushed_count]
        /\ children_before_parent' = [children_before_parent EXCEPT ![i] =
            flushed_count = child_total[i]]
    /\ post_dispatch_outcome_unknown' = [post_dispatch_outcome_unknown EXCEPT ![i] = TRUE]
    /\ terminal_kind' = [terminal_kind EXCEPT ![i] = "cancel"]
    /\ parent_append_state' = [parent_append_state EXCEPT ![i] = "construction-failed"]
    /\ parent_construction_failure' = [parent_construction_failure EXCEPT ![i] = "clock"]
    /\ UNCHANGED << admitted_resources, unwind_failed, child_total,
                     parent_append_attempts, parent_receipts, parent_kind_logged,
                     server_error_kind, nested_bridge_active_at_error >>

LifecycleNext ==
    \/ \E i \in Invocations : Admit(i)
    \/ \E i \in Invocations : StartDispatch(i)
    \/ \E i \in Invocations : StreamChunk(i)
    \/ \E i \in Invocations : CompleteOk(i)
    \/ \E i \in Invocations : DenyPostInvocation(i)
    \/ \E i \in Invocations : IncompleteStream(i)
    \/ \E i \in Invocations : ServerErrorPostDispatch(i)
    \/ \E i \in Invocations : DropPreDispatch(i)
    \/ \E i \in Invocations : DropPostDispatch(i)

Next ==
    \/ /\ LifecycleNext
       /\ UNCHANGED parent_construction_failure
    \/ \E i \in Invocations : DropPreDispatchConstructionFailed(i)
    \/ \E i \in Invocations : DropPostDispatchConstructionFailed(i)

Spec ==
    /\ Init
    /\ [][Next]_vars

ReservationConservation ==
    /\ CountedLedgerDomains
    /\ PartitionAtEveryState
    /\ ChildSplitsBounded
    /\ \A i \in Invocations :
        IsTerminal(i) => CountedLedger(i).outstanding = 0

TerminalReceiptExactlyOne ==
    \A i \in Invocations :
        /\ parent_append_state[i] = "not-attempted" =>
            /\ parent_append_attempts[i] = 0
            /\ parent_receipts[i] = 0
            /\ parent_kind_logged[i] = "none"
        /\ (parent_append_state[i] = "construction-failed") <=>
            (parent_construction_failure[i] = "clock")
        /\ parent_append_state[i] = "construction-failed" =>
            /\ phase[i] = "terminal_fault"
            /\ terminal_kind[i] \in {"fault", "cancel"}
            /\ parent_append_attempts[i] = 0
            /\ parent_receipts[i] = 0
            /\ parent_kind_logged[i] = "none"
        /\ parent_append_state[i] = "committed" =>
            /\ parent_append_attempts[i] = 1
            /\ parent_receipts[i] = 1
            /\ parent_kind_logged[i] = terminal_kind[i]
            /\ terminal_kind[i] \in ParentReceiptKinds
        /\ parent_append_state[i] = "outcome-unknown" =>
            /\ parent_append_attempts[i] = 1
            /\ parent_receipts[i] \in 0..1
            /\ parent_kind_logged[i] =
                IF parent_receipts[i] = 1 THEN terminal_kind[i] ELSE "none"
            /\ terminal_kind[i] \in ParentReceiptKinds
        /\ terminal_kind[i] \in {"none", "unwound"} =>
            parent_append_state[i] = "not-attempted"
        /\ terminal_kind[i] \in ParentReceiptKinds =>
            parent_append_state[i] \in {"construction-failed", "outcome-unknown", "committed"}

ChildReceiptsFlushed ==
    \A i \in Invocations :
        IsTerminal(i) =>
            /\ child_buf[i] = 0
            /\ child_logged[i] = child_total[i]
            /\ children_before_parent[i]

RetainedIffAborted ==
    \A i \in Invocations :
        /\ ( (ledger[i]["lease"] = "retained") <=>
             ( /\ "lease" \in admitted_resources[i]
               /\ \/ terminal_kind[i] \in {"deny", "incomplete", "cancel"}
                  \/ "lease" \in unwind_failed[i] ) )
        /\ ( (ledger[i]["hold"] = "retained") <=>
             ( /\ "hold" \in admitted_resources[i]
               /\ \/ post_dispatch_outcome_unknown[i]
                  \/ "hold" \in unwind_failed[i] ) )
        /\ (server_error_kind[i] = "url") =>
            /\ post_dispatch_outcome_unknown[i]
            /\ terminal_kind[i] = "incomplete"
            /\ phase[i] = "terminal_denied"

SafetyInv ==
    /\ DomainsOK
    /\ ReservationConservation
    /\ TerminalReceiptExactlyOne
    /\ ChildReceiptsFlushed
    /\ RetainedIffAborted

=============================================================================
