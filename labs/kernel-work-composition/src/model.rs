//! KW1 specification ports. No native execution, cryptography, networking or storage.
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub type Basis = [u16; 5];
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Confidentiality,
    Integrity,
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Approval {
    pub principal: u8,
    pub role: Role,
    pub basis: Basis,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReleaseClaim {
    pub principal: u8,
    pub channel: String,
    pub recipient: u8,
    pub version: u16,
    pub role: Role,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Fresh,
    Captured,
    Unknown,
    Applied,
    Partial,
    None,
}
impl Outcome {
    pub fn terminal(self) -> bool {
        matches!(self, Self::Applied | Self::Partial | Self::None)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Command {
    Approve {
        op: usize,
        principal: u8,
        role: Role,
        basis: Basis,
    },
    Finalize {
        op: usize,
        issuance: u64,
        envelope: u64,
    },
    Readback {
        op: usize,
        issuance: u64,
        envelope: u64,
    },
    Capture {
        op: usize,
        epoch: u64,
        mode: String,
    },
    Send {
        op: usize,
    },
    Change {
        field: String,
        value: u16,
    },
    Crash,
    Rollback {
        epoch: u64,
    },
    Lookup {
        op: usize,
    },
    Evidence {
        op: usize,
        signer: u8,
        key: u64,
        basis: Basis,
        outcome: Outcome,
        complete: bool,
        fenced: bool,
        retained: bool,
    },
    Permission {
        name: String,
        value: bool,
    },
    Settle {
        op: usize,
        epoch: u64,
    },
    ReadResult {
        op: usize,
    },
    Release {
        channel: String,
        recipient: u8,
        bounded: bool,
        claims: Vec<ReleaseClaim>,
    },
    ClearKnowledge,
    Translate {
        mapping: [u8; 4],
    },
    Dependency {
        dependency_kind: String,
        revision: u16,
        until: u64,
    },
    AdvanceDependency {
        revision: u16,
        time: u64,
    },
    Fund {
        id: u8,
        amount: u64,
        beneficiary: u8,
        predicate: u16,
        op: usize,
    },
    Accept {
        id: u8,
        beneficiary: u8,
        predicate: u16,
        op: usize,
        signer: u8,
    },
    Pay {
        id: u8,
    },
    RefundParent,
    Project {
        op: usize,
        outcome: Outcome,
    },
    Gc {
        op: usize,
    },
    Plan {
        limit: usize,
        registered: bool,
    },
}
#[derive(Clone, Debug, Serialize)]
pub struct Operation {
    pub basis: Basis,
    pub approvals: BTreeSet<Approval>,
    pub finalized: Option<(u64, u64, Basis)>,
    pub custody_uncertain: bool,
    pub captures: u64,
    pub nonces: u64,
    pub attempted: bool,
    pub outcome: Outcome,
    pub projection: Outcome,
    pub history: Vec<String>,
    pub settled: bool,
    pub quarantined: bool,
}
impl Default for Operation {
    fn default() -> Self {
        Self {
            basis: [1; 5],
            approvals: BTreeSet::new(),
            finalized: None,
            custody_uncertain: false,
            captures: 0,
            nonces: 0,
            attempted: false,
            outcome: Outcome::Fresh,
            projection: Outcome::Fresh,
            history: vec![],
            settled: false,
            quarantined: false,
        }
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct Dependency {
    pub kind: String,
    pub revision: u16,
    pub until: u64,
}
#[derive(Clone, Debug, Serialize)]
pub struct Funding {
    pub amount: u64,
    pub beneficiary: u8,
    pub predicate: u16,
    pub op: usize,
    pub earned: bool,
    pub paid: bool,
}
#[derive(Clone, Debug, Serialize)]
pub struct State {
    pub profile: String,
    pub ops: [Operation; 3],
    pub epoch: u64,
    pub knowledge: u8,
    pub child_knowledge: u8,
    pub translated: u8,
    pub releases: u64,
    pub reads: u64,
    pub caller: bool,
    pub read: bool,
    pub recovery: bool,
    pub connector: bool,
    pub metadata: bool,
    pub dependency: Option<Dependency>,
    pub dependency_revision: u16,
    pub time: u64,
    pub wallet: u64,
    pub funds: BTreeMap<u8, Funding>,
    pub parent_refund: u64,
    pub recovery_spent: u64,
    pub advice: String,
    pub unrelated: u16,
}
impl State {
    pub fn new(profile: &str, initial: &Value) -> Result<Self, String> {
        if !matches!(profile, "E1" | "E2") {
            return Err("unsupported effect profile".into());
        }
        let wallet = initial.get("wallet").and_then(Value::as_u64).unwrap_or(100);
        if wallet > 100 {
            return Err("KW1 wallet bound".into());
        }
        Ok(Self {
            profile: profile.into(),
            ops: std::array::from_fn(|_| Operation::default()),
            epoch: 1,
            knowledge: if initial.get("extra_component") == Some(&Value::Bool(true)) {
                11
            } else {
                3
            },
            child_knowledge: 0,
            translated: 0,
            releases: 0,
            reads: 0,
            caller: true,
            read: true,
            recovery: true,
            connector: true,
            metadata: true,
            dependency: None,
            dependency_revision: 1,
            time: 1,
            wallet,
            funds: BTreeMap::new(),
            parent_refund: 0,
            recovery_spent: 0,
            advice: "unplanned".into(),
            unrelated: 1,
        })
    }
    pub fn allocated(&self) -> u64 {
        self.funds.values().map(|f| f.amount).sum()
    }
    pub fn dependency_valid(&self) -> bool {
        self.dependency
            .as_ref()
            .is_none_or(|d| match d.kind.as_str() {
                "historical" => true,
                "current" => d.revision == self.dependency_revision,
                "held" => d.revision == self.dependency_revision && self.time < d.until,
                _ => false,
            })
    }
    pub fn view(&self) -> Value {
        let reserved = self
            .ops
            .iter()
            .filter(|o| o.outcome == Outcome::Captured)
            .count();
        let unresolved = self
            .ops
            .iter()
            .filter(|o| o.outcome == Outcome::Unknown)
            .count();
        let spent = self
            .ops
            .iter()
            .filter(|o| matches!(o.outcome, Outcome::Applied | Outcome::Partial))
            .count();
        let exposure = reserved + unresolved + spent + self.recovery_spent as usize;
        json!({"captures":self.ops.each_ref().map(|o|o.captures),"nonces":self.ops.each_ref().map(|o|o.nonces),
            "issuances":self.ops.each_ref().map(|o|o.finalized.map_or(0,|x|x.0)),
            "envelopes":self.ops.each_ref().map(|o|o.finalized.map_or(0,|x|x.1)),
            "outcomes":self.ops.each_ref().map(|o|o.outcome),"projection":self.ops.each_ref().map(|o|o.projection),
            "history":self.ops.each_ref().map(|o|&o.history),"settled":self.ops.each_ref().map(|o|o.settled),
            "quarantined":self.ops.each_ref().map(|o|o.quarantined),"knowledge":self.knowledge,
            "child_knowledge":self.child_knowledge,"translated":self.translated,"releases":self.releases,
            "reads":self.reads,"epoch":self.epoch,"exposure":exposure,"remaining":10usize.saturating_sub(exposure),
            "reserved":reserved,"unresolved":unresolved,"spent":spent,"recovery_spent":self.recovery_spent,
            "wallet":self.wallet,"wallet_reserved":self.allocated(),
            "earned":self.funds.values().filter(|f|f.earned).map(|f|f.amount).sum::<u64>(),
            "paid":self.funds.values().filter(|f|f.paid).map(|f|f.amount).sum::<u64>(),
            "parent_refund":self.parent_refund,"advice":self.advice})
    }
}
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Fault {
    #[serde(default)]
    pub at: usize,
    pub applied: Option<bool>,
    pub ack: Option<bool>,
    #[serde(default)]
    pub partial: bool,
    #[serde(default)]
    pub drop_ack: bool,
}
/// The oracle is deliberately not part of State or either decision function.
#[derive(Clone, Debug, Default, Serialize)]
pub struct Oracle {
    pub effects: [u64; 3],
}
fn append(op: &mut Operation, outcome: Outcome) {
    op.outcome = outcome;
    op.projection = outcome;
    let name = match outcome {
        Outcome::Fresh => "fresh",
        Outcome::Captured => "captured",
        Outcome::Unknown => "unknown",
        Outcome::Applied => "applied",
        Outcome::Partial => "partial",
        Outcome::None => "none",
    };
    op.history.push(name.into());
}
/// An admitted command enters its owning specification port. This is a shared
/// transition adapter, not an independently implemented production kernel.
pub fn apply(s: &mut State, c: &Command, allowed: bool, fault: &Fault, oracle: &mut Oracle) {
    if !allowed {
        if let Command::Evidence {
            op,
            signer,
            key,
            basis,
            outcome,
            complete,
            fenced,
            retained,
        } = c
            && let Some(o) = s.ops.get_mut(*op)
            && *signer == 9
            && *key == (*op as u64 + 1)
            && o.finalized.is_some_and(|f| f.2 == *basis)
            && *complete
            && *retained
            && (*outcome != Outcome::None || *fenced)
            && o.outcome.terminal()
            && outcome.terminal()
            && o.outcome != *outcome
        {
            o.quarantined = true;
            o.history.push("conflict".into());
        }
        return;
    }
    match c {
        Command::Approve {
            op,
            principal,
            role,
            basis,
        } => {
            s.ops[*op].approvals.insert(Approval {
                principal: *principal,
                role: role.clone(),
                basis: *basis,
            });
        }
        Command::Finalize {
            op,
            issuance,
            envelope,
        } => {
            let o = &mut s.ops[*op];
            o.finalized = Some((*issuance, *envelope, o.basis));
            o.custody_uncertain = fault.drop_ack;
        }
        Command::Readback { op, .. } => {
            s.ops[*op].custody_uncertain = false;
        }
        Command::Capture { op, .. } => {
            let o = &mut s.ops[*op];
            o.captures += 1;
            o.nonces += 1;
            o.outcome = Outcome::Captured;
            o.projection = Outcome::Captured;
        }
        Command::Send { op } => {
            let o = &mut s.ops[*op];
            o.attempted = true;
            let applied = fault.applied.unwrap_or(true);
            let ack = fault.ack.unwrap_or(true);
            if applied {
                oracle.effects[*op] += 1;
            }
            // Neither the decision function nor an unacknowledged observation
            // receives the hidden physical outcome.
            append(
                o,
                if !ack {
                    Outcome::Unknown
                } else if !applied {
                    Outcome::None
                } else if fault.partial {
                    Outcome::Partial
                } else {
                    Outcome::Applied
                },
            );
        }
        Command::Change { field, value } => {
            if let Some(i) = ["bytes", "recipient", "account", "policy", "acl"]
                .iter()
                .position(|v| v == field)
            {
                s.ops[0].basis[i] = *value;
            } else {
                s.unrelated = *value;
            }
        }
        Command::Crash => {
            s.epoch += 1;
            for o in &mut s.ops {
                if o.outcome == Outcome::Captured {
                    o.attempted = true;
                    append(o, Outcome::Unknown);
                }
            }
        }
        Command::Rollback { epoch } => s.epoch = *epoch,
        Command::Lookup { .. } => {
            s.recovery_spent += 1;
        }
        Command::Evidence { op, outcome, .. } => {
            let o = &mut s.ops[*op];
            if o.outcome != *outcome {
                append(o, *outcome);
            }
        }
        Command::Permission { name, value } => match name.as_str() {
            "caller" => s.caller = *value,
            "read" => s.read = *value,
            "recovery" => s.recovery = *value,
            "connector" => s.connector = *value,
            "metadata" => s.metadata = *value,
            _ => {}
        },
        Command::Settle { op, .. } => {
            s.ops[*op].settled = true;
        }
        Command::ReadResult { .. } => {
            s.reads += 1;
        }
        Command::Release { channel, .. } => {
            s.releases += 1;
            if channel == "seed" {
                s.child_knowledge |= s.knowledge;
            }
        }
        Command::ClearKnowledge => s.knowledge = 0,
        Command::Translate { mapping } => {
            s.translated = (0..4)
                .filter(|i| s.knowledge & (1 << i) != 0)
                .fold(0, |mask, i| mask | 1 << mapping[i]);
        }
        Command::Dependency {
            dependency_kind,
            revision,
            until,
        } => {
            s.dependency = Some(Dependency {
                kind: dependency_kind.clone(),
                revision: *revision,
                until: *until,
            });
        }
        Command::AdvanceDependency { revision, time } => {
            s.dependency_revision = *revision;
            s.time = *time;
        }
        Command::Fund {
            id,
            amount,
            beneficiary,
            predicate,
            op,
        } => {
            s.funds.entry(*id).or_insert(Funding {
                amount: *amount,
                beneficiary: *beneficiary,
                predicate: *predicate,
                op: *op,
                earned: false,
                paid: false,
            });
        }
        Command::Accept { id, .. } => {
            if let Some(f) = s.funds.get_mut(id) {
                f.earned = true;
            }
        }
        Command::Pay { id } => {
            if let Some(f) = s.funds.get_mut(id) {
                f.paid = true;
            }
        }
        Command::RefundParent => {
            s.parent_refund = 100;
        }
        Command::Project { op, outcome } => {
            s.ops[*op].projection = *outcome;
        }
        Command::Gc { .. } => {} // Payload GC never removes replay/identity/outcome tombstones.
        Command::Plan { limit, registered } => {
            s.advice = if *limit == 0 {
                "bound_reached"
            } else if !registered {
                "no_registered_remedy"
            } else {
                "candidates"
            }
            .into();
        }
    }
}
