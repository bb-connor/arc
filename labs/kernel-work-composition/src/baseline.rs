//! B1 direct service guards. Does not call the candidate obligation evaluator.
use crate::model::{Command, Outcome, Role, State};
/// Count top-level guard evaluations only, not CPU instructions or inner scans.
pub fn decide(s: &State, c: &Command) -> (bool, usize) {
    let mut count = 0;
    macro_rules! require {
        ($condition:expr) => {{
            count += 1;
            if !($condition) {
                return (false, count);
            }
        }};
    }
    match c {
        Command::Approve { op, principal, .. } => {
            require!(*op < 3);
            require!(*principal < 4);
        }
        Command::Finalize {
            op,
            issuance,
            envelope,
        } => {
            require!(*op < 3);
            require!(*issuance != 0 && *envelope != 0);
            for (index, other) in s.ops.iter().enumerate() {
                if index != *op
                    && let Some((used_issuance, used_envelope, _)) = other.finalized
                {
                    require!(used_issuance != *issuance && used_envelope != *envelope);
                }
            }
            if let Some((old_i, old_e, basis)) = s.ops[*op].finalized {
                require!(old_i == *issuance && old_e == *envelope && basis == s.ops[*op].basis);
            }
        }
        Command::Readback {
            op,
            issuance,
            envelope,
        } => {
            require!(*op < 3);
            require!(matches!(s.ops[*op].finalized,Some((i,e,_)) if i==*issuance && e==*envelope));
        }
        Command::Capture { op, epoch, mode } => {
            require!(*op < 3);
            let record = &s.ops[*op];
            require!(mode == "live" && *epoch == s.epoch && s.caller);
            require!(
                matches!(record.finalized,Some((_,_,b)) if b==record.basis)
                    && !record.custody_uncertain
            );
            let mut owners = 0u8;
            let mut endorsed = false;
            for a in &record.approvals {
                if a.basis != record.basis {
                    continue;
                }
                if a.role == Role::Integrity && a.principal == 2 {
                    endorsed = true;
                }
                if a.role == Role::Confidentiality && a.principal < 4 {
                    owners |= 1 << a.principal;
                }
            }
            require!(owners & s.knowledge == s.knowledge && endorsed);
            require!(record.captures == 0 && !record.quarantined);
            if let Some(d) = &s.dependency
                && *op == 0
            {
                match d.kind.as_str() {
                    "historical" => {}
                    "current" => require!(d.revision == s.dependency_revision),
                    "held" => require!(d.revision == s.dependency_revision && d.until > s.time),
                    _ => return (false, count),
                }
            }
        }
        Command::Send { op } => {
            require!(*op < 3);
            let o = &s.ops[*op];
            require!(o.captures == 1 && !o.attempted && !o.quarantined);
        }
        Command::Change { field, .. } => require!(matches!(
            field.as_str(),
            "bytes" | "recipient" | "account" | "policy" | "acl" | "unrelated"
        )),
        Command::Crash => require!(s.epoch != u64::MAX),
        Command::Rollback { epoch } => require!(*epoch == s.epoch),
        Command::Lookup { op } => {
            require!(*op < 3);
            require!(s.profile == "E1" && s.connector && s.recovery);
            require!(s.recovery_spent < 3 && s.ops[*op].attempted);
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
            require!(*op < 3);
            let o = &s.ops[*op];
            require!(s.profile == "E1");
            require!(*signer == 9 && *key == *op as u64 + 1);
            require!(matches!(o.finalized,Some((_,_,b)) if b==*basis));
            require!(o.attempted && *complete && *retained);
            require!(matches!(
                outcome,
                Outcome::Applied | Outcome::Partial | Outcome::None
            ));
            require!(*outcome != Outcome::None || *fenced);
            require!(!o.outcome.terminal() || o.outcome == *outcome);
            require!(!o.quarantined);
        }
        Command::Permission { name, .. } => require!(matches!(
            name.as_str(),
            "caller" | "read" | "recovery" | "connector" | "metadata"
        )),
        Command::Settle { op, epoch } => {
            require!(*op < 3);
            require!(*epoch == s.epoch && s.recovery && s.ops[*op].attempted);
        }
        Command::ReadResult { op } => {
            require!(*op < 3);
            require!(s.read && s.ops[*op].outcome == Outcome::Applied && !s.ops[*op].quarantined);
        }
        Command::Release {
            channel,
            recipient,
            bounded,
            claims,
        } => {
            require!(matches!(
                channel.as_str(),
                "seed"
                    | "return"
                    | "result"
                    | "error"
                    | "metadata"
                    | "log"
                    | "payment"
                    | "approval"
            ));
            require!(*recipient == 5 && (channel != "return" || *bounded) && claims.len() <= 16);
            require!(channel != "result" || s.read);
            let mut represented = 0u8;
            for approval in claims {
                if approval.channel == *channel
                    && approval.recipient == *recipient
                    && approval.version == 1
                    && approval.role == Role::Confidentiality
                    && approval.principal < 4
                {
                    represented |= 1 << approval.principal;
                }
            }
            require!(represented & s.knowledge == s.knowledge);
        }
        Command::ClearKnowledge => return (false, 1),
        Command::Translate { mapping } => require!(matches!(*mapping, [0, 1, 2, 3] | [1, 0, 2, 3])),
        Command::Dependency {
            dependency_kind, ..
        } => require!(matches!(
            dependency_kind.as_str(),
            "historical" | "current" | "held"
        )),
        Command::AdvanceDependency { time, .. } => require!(*time >= s.time),
        Command::Fund {
            id,
            amount,
            beneficiary,
            predicate,
            op,
        } => {
            require!(
                *id < 16
                    && *amount > 0
                    && *amount <= 100
                    && *op < 3
                    && *beneficiary == 7
                    && *predicate == 1
            );
            if let Some(f) = s.funds.get(id) {
                require!(
                    f.amount == *amount
                        && f.beneficiary == *beneficiary
                        && f.predicate == *predicate
                        && f.op == *op
                );
            } else {
                require!(
                    *amount
                        <= s.wallet
                            .saturating_sub(s.funds.values().map(|f| f.amount).sum())
                );
            }
        }
        Command::Accept {
            id,
            beneficiary,
            predicate,
            op,
            signer,
        } => {
            require!(*signer == 8);
            if let Some(f) = s.funds.get(id) {
                require!(f.beneficiary == *beneficiary && f.predicate == *predicate && f.op == *op);
            } else {
                return (false, count);
            }
        }
        Command::Pay { id } => {
            require!(s.metadata);
            require!(s.funds.get(id).is_some_and(|f| f.earned));
        }
        Command::RefundParent => {}
        Command::Project { op, outcome } => {
            require!(*op < 3);
            require!(s.ops[*op].outcome == *outcome);
        }
        Command::Gc { op } => {
            require!(*op < 3);
            require!(s.ops[*op].outcome.terminal());
        }
        Command::Plan { limit, .. } => require!(*limit <= 16),
    }
    (true, count)
}
