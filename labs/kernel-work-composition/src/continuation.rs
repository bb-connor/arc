//! Candidate obligation frontier. All inputs are controller-visible records.
use crate::model::{Command, Outcome, Role, State};
#[derive(Clone, Debug)]
pub struct Check {
    pub rule: &'static str,
    pub holds: bool,
}
pub fn obligations(s: &State, c: &Command) -> Vec<Check> {
    let mut checks = Vec::new();
    macro_rules! check {
        ($rule:expr,$value:expr) => {{
            checks.push(Check {
                rule: $rule,
                holds: $value,
            });
        }};
    }
    let op = match c {
        Command::Approve { op, .. }
        | Command::Finalize { op, .. }
        | Command::Readback { op, .. }
        | Command::Capture { op, .. }
        | Command::Send { op }
        | Command::Lookup { op }
        | Command::Evidence { op, .. }
        | Command::Settle { op, .. }
        | Command::ReadResult { op }
        | Command::Project { op, .. }
        | Command::Gc { op } => Some(*op),
        _ => None,
    };
    if let Some(i) = op {
        check!("valid_operation", i < 3);
        if i >= 3 {
            return checks;
        }
    }
    match c {
        Command::Approve { principal, .. } => check!("principal", *principal < 4),
        Command::Finalize {
            op,
            issuance,
            envelope,
        } => {
            let o = &s.ops[*op];
            check!("identity", *issuance > 0 && *envelope > 0);
            check!(
                "identity_owner",
                s.ops.iter().enumerate().all(|(index, other)| index == *op
                    || other
                        .finalized
                        .is_none_or(|f| f.0 != *issuance && f.1 != *envelope))
            );
            check!(
                "custody",
                o.finalized
                    .is_none_or(|f| f == (*issuance, *envelope, o.basis))
            );
        }
        Command::Readback {
            op,
            issuance,
            envelope,
        } => check!(
            "custody",
            s.ops[*op]
                .finalized
                .is_some_and(|f| f.0 == *issuance && f.1 == *envelope)
        ),
        Command::Capture { op, epoch, mode } => {
            let o = &s.ops[*op];
            check!("live_mode", mode == "live");
            check!("epoch", *epoch == s.epoch);
            check!("caller", s.caller);
            check!(
                "custody",
                o.finalized.is_some_and(|f| f.2 == o.basis) && !o.custody_uncertain
            );
            let coverage = (0..4).filter(|i| s.knowledge & (1 << i) != 0).all(|i| {
                o.approvals.iter().any(|a| {
                    a.principal == i && a.role == Role::Confidentiality && a.basis == o.basis
                })
            });
            let integrity = o
                .approvals
                .iter()
                .any(|a| a.principal == 2 && a.role == Role::Integrity && a.basis == o.basis);
            check!("owners", coverage && integrity);
            check!("capture_once", o.captures == 0);
            check!("lifetime", *op != 0 || s.dependency_valid());
            check!("quarantine", !o.quarantined);
        }
        Command::Send { op } => {
            let o = &s.ops[*op];
            check!("captured", o.captures == 1);
            check!("one_send", !o.attempted);
            check!("quarantine", !o.quarantined);
        }
        Command::Change { field, .. } => check!(
            "field",
            [
                "bytes",
                "recipient",
                "account",
                "policy",
                "acl",
                "unrelated"
            ]
            .contains(&field.as_str())
        ),
        Command::Crash => check!("epoch_capacity", s.epoch < u64::MAX),
        Command::Rollback { epoch } => check!("anti_rollback", *epoch == s.epoch),
        Command::Lookup { op } => {
            check!("lookup_profile", s.profile == "E1");
            check!("connector", s.connector && s.recovery);
            check!("lookup_budget", s.recovery_spent < 3);
            check!("original", s.ops[*op].attempted);
        }
        Command::Evidence {
            op,
            signer,
            key,
            basis,
            outcome,
            complete,
            fenced,
            retained,
        } => {
            let o = &s.ops[*op];
            check!("lookup_profile", s.profile == "E1");
            check!(
                "evidence_context",
                *signer == 9
                    && *key == *op as u64 + 1
                    && o.finalized.is_some_and(|f| f.2 == *basis)
            );
            check!("original", o.attempted);
            check!(
                "closure",
                *complete && *retained && (*outcome != Outcome::None || *fenced)
            );
            check!("terminal_evidence", outcome.terminal());
            check!("consistent", !o.outcome.terminal() || o.outcome == *outcome);
            check!("quarantine", !o.quarantined);
        }
        Command::Permission { name, .. } => check!(
            "permission",
            ["caller", "read", "recovery", "connector", "metadata"].contains(&name.as_str())
        ),
        Command::Settle { op, epoch } => {
            check!("epoch", *epoch == s.epoch);
            check!("recovery", s.recovery);
            check!("original", s.ops[*op].attempted);
        }
        Command::ReadResult { op } => {
            check!("audience", s.read);
            check!(
                "available",
                s.ops[*op].outcome == Outcome::Applied && !s.ops[*op].quarantined
            );
        }
        Command::Release {
            channel,
            recipient,
            bounded,
            claims,
        } => {
            check!(
                "channel",
                [
                    "seed", "return", "result", "error", "metadata", "log", "payment", "approval"
                ]
                .contains(&channel.as_str())
            );
            check!("receiver", *recipient == 5);
            check!("audience", channel != "result" || s.read);
            check!("bounded", channel != "return" || *bounded);
            check!("claim_bound", claims.len() <= 16);
            check!(
                "owners",
                (0..4)
                    .filter(|i| s.knowledge & (1 << i) != 0)
                    .all(|i| claims.iter().any(|a| a.principal == i
                        && a.role == Role::Confidentiality
                        && a.channel == *channel
                        && a.recipient == *recipient
                        && a.version == 1))
            );
        }
        Command::ClearKnowledge => check!("knowledge_monotonic", false),
        Command::Translate { mapping } => check!(
            "translation",
            *mapping == [0, 1, 2, 3] || *mapping == [1, 0, 2, 3]
        ),
        Command::Dependency {
            dependency_kind, ..
        } => check!(
            "dependency_kind",
            ["historical", "current", "held"].contains(&dependency_kind.as_str())
        ),
        Command::AdvanceDependency { time, .. } => check!("time", *time >= s.time),
        Command::Fund {
            id,
            amount,
            beneficiary,
            predicate,
            op,
        } => {
            check!(
                "fund_bounds",
                *id < 16
                    && *amount > 0
                    && *amount <= 100
                    && *op < 3
                    && *beneficiary == 7
                    && *predicate == 1
            );
            check!(
                "fund_identity",
                s.funds.get(id).is_none_or(|f| f.amount == *amount
                    && f.beneficiary == *beneficiary
                    && f.predicate == *predicate
                    && f.op == *op)
            );
            check!(
                "backing",
                s.funds.contains_key(id) || *amount <= s.wallet.saturating_sub(s.allocated())
            );
        }
        Command::Accept {
            id,
            beneficiary,
            predicate,
            op,
            signer,
        } => {
            check!(
                "acceptance",
                *signer == 8
                    && s.funds
                        .get(id)
                        .is_some_and(|f| f.beneficiary == *beneficiary
                            && f.predicate == *predicate
                            && f.op == *op)
            );
        }
        Command::Pay { id } => {
            check!("earned", s.funds.get(id).is_some_and(|f| f.earned));
            check!("observers", s.metadata);
        }
        Command::RefundParent => check!("parent_contract", true),
        Command::Project { op, outcome } => check!("projection", s.ops[*op].outcome == *outcome),
        Command::Gc { op } => check!("retention", s.ops[*op].outcome.terminal()),
        Command::Plan { limit, .. } => check!("planner_bound", *limit <= 16),
    }
    checks
}
