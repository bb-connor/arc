------------------------- MODULE ResponseLifecycle -------------------------
(***************************************************************************)
(* Bounded lifecycle model for active-response plans: dispatch, effect      *)
(* application, owner loss, partial acknowledgement, expiry, rollback and   *)
(* lift, for two plans whose effects overlap on one target.                 *)
(*                                                                          *)
(* Action               Rust implementation                                 *)
(* Simulate             signed simulation report for a dry-run plan; the    *)
(*                      report path shares no live variable with dispatch  *)
(* Dispatch             prepare_response_dispatch;                          *)
(*                      ResponseDispatchStore::commit_dispatch              *)
(* RequestEffect        ResponseStateMachine::record_effect_with_receipt_scheduled *)
(*                      with EffectMutation::Requested                      *)
(* ExecuteEffect        ResponseExecutor::execute effect journal commit;    *)
(*                      ContainmentOverlayStore::apply_contribution         *)
(* AcknowledgeEffect    record_effect_with_receipt_scheduled with           *)
(*                      EffectMutation::Applied or Failed, bound to the     *)
(*                      durable effect transition it acknowledges           *)
(* Activate             ResponseStateMachine::transition_scheduled to Active *)
(* LoseOwner, Claim     scheduler lease expiry; ResponseScheduler::claim    *)
(* ApplyTimeout         handle_due_scheduled at the applying lease deadline *)
(* FailResponse         transition_scheduled to Failed or ApplyPartial      *)
(* Tick, Expire         handle_due_scheduled at plan expiry                 *)
(* BeginRollback        transition_scheduled to RollingBack                 *)
(* RequestRollback      record_effect with EffectMutation::RollbackRequested *)
(* ExecuteRollback      effect journal commit;                              *)
(*                      ContainmentOverlayStore::remove_contribution        *)
(* AcknowledgeRollback  record_effect with RollbackRestored or RollbackFailed *)
(* Lift                 transition to Lifted under                          *)
(*                      ResponseSnapshot::all_applied_reversible_effects_restored *)
(* PageOperator         transition to RollbackPartial                       *)
(* RetryRollback        transition RollbackPartial to RollingBack           *)
(* Cancel               transition to Cancelled                             *)
(*                                                                          *)
(* The response log (`effect`, `state`) is what receipts claim. The effect  *)
(* journal (`journal`) and the overlay (`overlay`, `restricted`) are what   *)
(* durably happened. Execution and rollback land in the journal without an  *)
(* owner because an in-flight request completes after the lease that       *)
(* issued it is lost; only a live owner may acknowledge, and an             *)
(* acknowledgement must read the journal. Acknowledging a not-executed      *)
(* outcome is therefore a journal read, never a guess.                      *)
(*                                                                          *)
(* Every effect is reversible; the model does not carry the irreversible    *)
(* EscalateAlert kind, so a lift requires every applied effect restored.    *)
(* Both approval modes reach Applying through one dispatch commit; the      *)
(* approval coordinator boundary is outside this model.                     *)
(*                                                                          *)
(* Invariants:                                                              *)
(*   DryRunIsolation      a dry-run plan never commits dispatch work, owns  *)
(*                        a lease, executes, or installs a contribution     *)
(*   NoFalseCleanLift     Lifted implies every applied effect is restored   *)
(*                        and no contribution of the plan remains installed *)
(*   OverlapPreserved     a target is restricted exactly when some plan     *)
(*                        still holds an installed contribution on it       *)
(*   ReceiptStateTruthful every response-log claim agrees with the journal  *)
(*                        and the overlay at every reachable state          *)
(*   LiveWorkIsCommitted  execution states exist only behind a committed    *)
(*                        dispatch                                          *)
(*                                                                          *)
(* Negative variants under _negative_tests select one Mutation each and     *)
(* must falsify exactly the named invariant.                                *)
(***************************************************************************)

EXTENDS Naturals, FiniteSets

CONSTANTS
    \* @type: Set(Int);
    Actions,
    \* @type: Set(Int);
    Targets,
    \* @type: Set(Int);
    Workers,
    \* @type: Int;
    ExpiresAt,
    \* @type: Int;
    ClockMax,
    \* @type: Str;
    Mutation

Modes == {"live", "dry_run"}

States == {
    "planned",
    "simulated",
    "applying",
    "active",
    "apply_partial",
    "expiring",
    "rolling_back",
    "rollback_partial",
    "cancelled",
    "expired",
    "failed",
    "lifted"
}

EffectStates == {
    "none",
    "planned",
    "requested",
    "applied",
    "apply_failed",
    "rollback_requested",
    "restored",
    "rollback_failed"
}

JournalStates == {"none", "applied", "failed", "restored", "restore_failed"}

Mutations == {
    "none",
    "dispatch-dry-run",
    "acknowledge-unexecuted",
    "guess-not-executed",
    "timeout-unresolved",
    "activate-unacknowledged",
    "lift-unrestored",
    "clear-on-remove"
}

ASSUME
    /\ Actions = 1..2
    /\ Targets = 1..2
    /\ Cardinality(Workers) >= 1
    /\ 0 \notin Workers
    /\ ExpiresAt >= 1
    /\ ClockMax >= ExpiresAt
    /\ Mutation \in Mutations

\* Plan 1 restricts both targets; plan 2 restricts target 1 only, so the
\* two plans overlap on target 1 and plan 1 has one non-overlapping effect.
Effects == [a \in Actions |-> IF a = 1 THEN Targets ELSE {1}]

VARIABLES
    \* @type: Int -> Str;
    mode,
    \* @type: Int -> Str;
    state,
    \* @type: Int -> (Int -> Str);
    effect,
    \* @type: Int -> (Int -> Str);
    journal,
    \* @type: Int -> Set(Int);
    overlay,
    \* @type: Int -> Bool;
    restricted,
    \* @type: Int -> Str;
    dispatch,
    \* @type: Int -> Int;
    owner,
    \* @type: Int;
    clock

vars == <<mode, state, effect, journal, overlay, restricted, dispatch, owner, clock>>

Init ==
    /\ mode \in [Actions -> Modes]
    /\ state = [a \in Actions |-> "planned"]
    /\ effect = [a \in Actions |->
        [t \in Targets |-> IF t \in Effects[a] THEN "planned" ELSE "none"]]
    /\ journal = [a \in Actions |-> [t \in Targets |-> "none"]]
    /\ overlay = [t \in Targets |-> {}]
    /\ restricted = [t \in Targets |-> FALSE]
    /\ dispatch = [a \in Actions |-> "none"]
    /\ owner = [a \in Actions |-> 0]
    /\ clock = 0

AnyApplied(a) == \E t \in Effects[a] : effect[a][t] = "applied"

AnyRequested(a) == \E t \in Effects[a] : effect[a][t] = "requested"

Simulate(a) ==
    /\ mode[a] = "dry_run"
    /\ state[a] = "planned"
    /\ state' = [state EXCEPT ![a] = "simulated"]
    /\ UNCHANGED <<mode, effect, journal, overlay, restricted, dispatch, owner, clock>>

Dispatch(a, w) ==
    /\ \/ mode[a] = "live"
       \/ Mutation = "dispatch-dry-run"
    /\ state[a] = "planned"
    /\ clock < ExpiresAt
    /\ w \in Workers
    /\ state' = [state EXCEPT ![a] = "applying"]
    /\ dispatch' = [dispatch EXCEPT ![a] = "committed"]
    /\ owner' = [owner EXCEPT ![a] = w]
    /\ UNCHANGED <<mode, effect, journal, overlay, restricted, clock>>

RequestEffect(a, t) ==
    /\ state[a] = "applying"
    /\ owner[a] # 0
    /\ t \in Effects[a]
    /\ effect[a][t] = "planned"
    /\ \A u \in Effects[a] : effect[a][u] \notin {"requested", "apply_failed"}
    /\ effect' = [effect EXCEPT ![a][t] = "requested"]
    /\ UNCHANGED <<mode, state, journal, overlay, restricted, dispatch, owner, clock>>

\* A requested effect lands in the journal whenever the external system
\* completes it, with or without a live owner, until the journal resolves.
ExecuteEffect(a, t, ok) ==
    /\ t \in Effects[a]
    /\ effect[a][t] # "planned"
    /\ journal[a][t] = "none"
    /\ ok \in BOOLEAN
    /\ journal' = [journal EXCEPT ![a][t] = IF ok THEN "applied" ELSE "failed"]
    /\ overlay' = IF ok THEN [overlay EXCEPT ![t] = @ \cup {a}] ELSE overlay
    /\ restricted' = IF ok THEN [restricted EXCEPT ![t] = TRUE] ELSE restricted
    /\ UNCHANGED <<mode, state, effect, dispatch, owner, clock>>

AcknowledgeEffect(a, t) ==
    /\ state[a] = "applying"
    /\ owner[a] # 0
    /\ t \in Effects[a]
    /\ effect[a][t] = "requested"
    /\ \/ /\ journal[a][t] = "applied"
          /\ effect' = [effect EXCEPT ![a][t] = "applied"]
       \/ /\ journal[a][t] = "failed"
          /\ effect' = [effect EXCEPT ![a][t] = "apply_failed"]
       \/ /\ Mutation = "acknowledge-unexecuted"
          /\ journal[a][t] = "none"
          /\ effect' = [effect EXCEPT ![a][t] = "applied"]
       \/ /\ Mutation = "guess-not-executed"
          /\ effect' = [effect EXCEPT ![a][t] = "apply_failed"]
    /\ UNCHANGED <<mode, state, journal, overlay, restricted, dispatch, owner, clock>>

Activate(a) ==
    /\ state[a] = "applying"
    /\ owner[a] # 0
    /\ \/ \A t \in Effects[a] : effect[a][t] = "applied"
       \/ /\ Mutation = "activate-unacknowledged"
          /\ \A t \in Effects[a] : effect[a][t] \in {"applied", "requested"}
    /\ state' = [state EXCEPT ![a] = "active"]
    /\ UNCHANGED <<mode, effect, journal, overlay, restricted, dispatch, owner, clock>>

LoseOwner(a) ==
    /\ owner[a] # 0
    /\ owner' = [owner EXCEPT ![a] = 0]
    /\ UNCHANGED <<mode, state, effect, journal, overlay, restricted, dispatch, clock>>

Claim(a, w) ==
    /\ owner[a] = 0
    /\ state[a] \in {"applying", "rolling_back"}
    /\ w \in Workers
    /\ owner' = [owner EXCEPT ![a] = w]
    /\ UNCHANGED <<mode, state, effect, journal, overlay, restricted, dispatch, clock>>

\* The applying lease is lost. Production closes the response only once
\* every issued effect has resolved; an unresolved request keeps it open.
ApplyTimeout(a) ==
    /\ state[a] = "applying"
    /\ owner[a] = 0
    /\ \/ ~AnyRequested(a)
       \/ Mutation = "timeout-unresolved"
    /\ state' = [state EXCEPT ![a] = IF AnyApplied(a) THEN "apply_partial" ELSE "failed"]
    /\ UNCHANGED <<mode, effect, journal, overlay, restricted, dispatch, owner, clock>>

FailResponse(a) ==
    /\ state[a] = "applying"
    /\ owner[a] # 0
    /\ \E t \in Effects[a] : effect[a][t] = "apply_failed"
    /\ ~AnyRequested(a)
    /\ state' = [state EXCEPT ![a] = IF AnyApplied(a) THEN "apply_partial" ELSE "failed"]
    /\ UNCHANGED <<mode, effect, journal, overlay, restricted, dispatch, owner, clock>>

Tick ==
    /\ clock < ClockMax
    /\ clock' = clock + 1
    /\ UNCHANGED <<mode, state, effect, journal, overlay, restricted, dispatch, owner>>

Expire(a) ==
    /\ clock >= ExpiresAt
    /\ \/ /\ state[a] = "planned"
          /\ state' = [state EXCEPT ![a] = "expired"]
       \/ /\ state[a] = "active"
          /\ state' = [state EXCEPT ![a] = "expiring"]
    /\ UNCHANGED <<mode, effect, journal, overlay, restricted, dispatch, owner, clock>>

BeginRollback(a) ==
    /\ state[a] \in {"active", "expiring", "apply_partial"}
    /\ state' = [state EXCEPT ![a] = "rolling_back"]
    /\ UNCHANGED <<mode, effect, journal, overlay, restricted, dispatch, owner, clock>>

RequestRollback(a, t) ==
    /\ state[a] = "rolling_back"
    /\ owner[a] # 0
    /\ t \in Effects[a]
    /\ effect[a][t] \in {"applied", "rollback_failed"}
    /\ effect' = [effect EXCEPT ![a][t] = "rollback_requested"]
    /\ UNCHANGED <<mode, state, journal, overlay, restricted, dispatch, owner, clock>>

ExecuteRollback(a, t, ok) ==
    /\ t \in Effects[a]
    /\ effect[a][t] = "rollback_requested"
    /\ journal[a][t] \in {"applied", "restore_failed"}
    /\ ok \in BOOLEAN
    /\ journal' = [journal EXCEPT ![a][t] = IF ok THEN "restored" ELSE "restore_failed"]
    /\ overlay' = IF ok THEN [overlay EXCEPT ![t] = @ \ {a}] ELSE overlay
    /\ restricted' =
        IF ~ok THEN restricted
        ELSE IF Mutation = "clear-on-remove" THEN [restricted EXCEPT ![t] = FALSE]
        ELSE [restricted EXCEPT ![t] = (overlay[t] \ {a}) # {}]
    /\ UNCHANGED <<mode, state, effect, dispatch, owner, clock>>

AcknowledgeRollback(a, t) ==
    /\ state[a] = "rolling_back"
    /\ owner[a] # 0
    /\ t \in Effects[a]
    /\ effect[a][t] = "rollback_requested"
    /\ \/ /\ journal[a][t] = "restored"
          /\ effect' = [effect EXCEPT ![a][t] = "restored"]
       \/ /\ journal[a][t] = "restore_failed"
          /\ effect' = [effect EXCEPT ![a][t] = "rollback_failed"]
    /\ UNCHANGED <<mode, state, journal, overlay, restricted, dispatch, owner, clock>>

Lift(a) ==
    /\ state[a] = "rolling_back"
    /\ owner[a] # 0
    /\ \/ \A t \in Effects[a] : effect[a][t] \in {"planned", "apply_failed", "restored"}
       \/ Mutation = "lift-unrestored"
    /\ state' = [state EXCEPT ![a] = "lifted"]
    /\ UNCHANGED <<mode, effect, journal, overlay, restricted, dispatch, owner, clock>>

PageOperator(a) ==
    /\ state[a] = "rolling_back"
    /\ \E t \in Effects[a] : effect[a][t] = "rollback_failed"
    /\ \A t \in Effects[a] : effect[a][t] # "rollback_requested"
    /\ state' = [state EXCEPT ![a] = "rollback_partial"]
    /\ UNCHANGED <<mode, effect, journal, overlay, restricted, dispatch, owner, clock>>

RetryRollback(a) ==
    /\ state[a] = "rollback_partial"
    /\ state' = [state EXCEPT ![a] = "rolling_back"]
    /\ UNCHANGED <<mode, effect, journal, overlay, restricted, dispatch, owner, clock>>

Cancel(a) ==
    /\ state[a] = "planned"
    /\ state' = [state EXCEPT ![a] = "cancelled"]
    /\ UNCHANGED <<mode, effect, journal, overlay, restricted, dispatch, owner, clock>>

Stutter == UNCHANGED vars

Next ==
    \/ \E a \in Actions : Simulate(a)
    \/ \E a \in Actions, w \in Workers : Dispatch(a, w)
    \/ \E a \in Actions, t \in Targets : RequestEffect(a, t)
    \/ \E a \in Actions, t \in Targets, ok \in BOOLEAN : ExecuteEffect(a, t, ok)
    \/ \E a \in Actions, t \in Targets : AcknowledgeEffect(a, t)
    \/ \E a \in Actions : Activate(a)
    \/ \E a \in Actions : LoseOwner(a)
    \/ \E a \in Actions, w \in Workers : Claim(a, w)
    \/ \E a \in Actions : ApplyTimeout(a)
    \/ \E a \in Actions : FailResponse(a)
    \/ Tick
    \/ \E a \in Actions : Expire(a)
    \/ \E a \in Actions : BeginRollback(a)
    \/ \E a \in Actions, t \in Targets : RequestRollback(a, t)
    \/ \E a \in Actions, t \in Targets, ok \in BOOLEAN : ExecuteRollback(a, t, ok)
    \/ \E a \in Actions, t \in Targets : AcknowledgeRollback(a, t)
    \/ \E a \in Actions : Lift(a)
    \/ \E a \in Actions : PageOperator(a)
    \/ \E a \in Actions : RetryRollback(a)
    \/ \E a \in Actions : Cancel(a)
    \/ Stutter

Spec ==
    /\ Init
    /\ [][Next]_vars

DomainsOK ==
    /\ Mutation \in Mutations
    /\ \A a \in Actions :
        /\ mode[a] \in Modes
        /\ state[a] \in States
        /\ dispatch[a] \in {"none", "committed"}
        /\ owner[a] \in Workers \cup {0}
        /\ \A t \in Targets :
            /\ effect[a][t] \in EffectStates
            /\ (effect[a][t] = "none") <=> (t \notin Effects[a])
            /\ journal[a][t] \in JournalStates
            /\ (t \notin Effects[a]) => journal[a][t] = "none"
    /\ \A t \in Targets : overlay[t] \subseteq Actions
    /\ clock \in 0..ClockMax

Untouched == {"planned", "simulated", "expired", "cancelled"}

DryRunIsolation ==
    \A a \in Actions : mode[a] = "dry_run" =>
        /\ dispatch[a] = "none"
        /\ owner[a] = 0
        /\ state[a] \in Untouched
        /\ \A t \in Targets :
            /\ a \notin overlay[t]
            /\ journal[a][t] = "none"
            /\ effect[a][t] \in {"none", "planned"}

NoFalseCleanLift ==
    \A a \in Actions : state[a] = "lifted" =>
        \A t \in Effects[a] :
            /\ a \notin overlay[t]
            /\ effect[a][t] \in {"planned", "apply_failed", "restored"}
            /\ journal[a][t] \in {"none", "failed", "restored"}

OverlapPreserved ==
    \A t \in Targets : restricted[t] <=> (overlay[t] # {})

ReceiptStateTruthful ==
    \A a \in Actions :
        /\ \A t \in Effects[a] :
            /\ (effect[a][t] = "planned") => (journal[a][t] = "none")
            /\ (effect[a][t] = "applied") => (journal[a][t] = "applied")
            /\ (effect[a][t] = "apply_failed") => (journal[a][t] = "failed")
            /\ (effect[a][t] = "restored") => (journal[a][t] = "restored")
            /\ (effect[a][t] = "rollback_failed") => (journal[a][t] = "restore_failed")
            /\ (a \in overlay[t]) <=> (journal[a][t] \in {"applied", "restore_failed"})
        /\ (state[a] = "active") => \A t \in Effects[a] : effect[a][t] = "applied"
        /\ (state[a] \in {"failed", "expired", "cancelled", "simulated"}) =>
            \A t \in Effects[a] : a \notin overlay[t] /\ effect[a][t] # "requested"
        /\ (state[a] = "rollback_partial") => \E t \in Effects[a] : effect[a][t] = "rollback_failed"
        /\ (state[a] = "apply_partial") => AnyApplied(a)

LiveWorkIsCommitted ==
    \A a \in Actions : state[a] \notin Untouched => dispatch[a] = "committed"

\* Rejected candidate, kept outside SafetyInv. A lifted plan does not clear a
\* target on which another plan still holds an installed contribution; the
\* registered witness reaches exactly that overlap so later documentation
\* cannot revive the candidate.
LiftedPlanClearsItsTargets ==
    \A a \in Actions : state[a] = "lifted" => \A t \in Effects[a] : ~restricted[t]

SafetyInv ==
    /\ DomainsOK
    /\ DryRunIsolation
    /\ NoFalseCleanLift
    /\ OverlapPreserved
    /\ ReceiptStateTruthful
    /\ LiveWorkIsCommitted

=============================================================================
