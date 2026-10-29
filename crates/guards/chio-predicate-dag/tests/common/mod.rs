#![allow(dead_code)]

use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard};

use chio_fixed::Q16_16;
use chio_predicate_dag::{
    Outcome, RulePolarity, ScheduleStorage, TriSet, Trit, ATOM_WORDS, MAX_ATOMS,
};

static STORAGE: Mutex<ScheduleStorage> = Mutex::new(ScheduleStorage::empty());

/// The shared schedule storage; it is too large for a test thread's stack.
pub fn storage() -> MutexGuard<'static, ScheduleStorage> {
    STORAGE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Lit {
    Atom { id: u16, negated: bool },
    Rule { id: u16, negated: bool },
}

#[derive(Clone, Debug)]
pub struct Rule {
    pub polarity: RulePolarity,
    pub clauses: Vec<Vec<Lit>>,
}

#[derive(Clone, Debug)]
pub struct Model {
    /// `(tau_neg, tau_pos)` bits per atom.
    pub thresholds: Vec<(i32, i32)>,
    pub rules: Vec<Rule>,
}

pub const CODE_ATOM_POS: u8 = 1;
pub const CODE_ATOM_NEG: u8 = 2;
pub const CODE_RULE_POS: u8 = 3;
pub const CODE_RULE_NEG: u8 = 4;
pub const CODE_END_CLAUSE: u8 = 5;
pub const CODE_END_RULE: u8 = 6;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RawOp {
    pub code: u8,
    pub word: u8,
    pub arg: u16,
    pub mask: u64,
}

impl RawOp {
    pub fn atoms(negated: bool, word: u8, mask: u64) -> Self {
        let code = if negated {
            CODE_ATOM_NEG
        } else {
            CODE_ATOM_POS
        };
        Self {
            code,
            word,
            arg: 0,
            mask,
        }
    }
    pub fn rule(negated: bool, id: u16) -> Self {
        let code = if negated {
            CODE_RULE_NEG
        } else {
            CODE_RULE_POS
        };
        Self {
            code,
            word: 0,
            arg: id,
            mask: 0,
        }
    }
    pub fn end_clause() -> Self {
        Self {
            code: CODE_END_CLAUSE,
            word: 0,
            arg: 0,
            mask: 0,
        }
    }
    pub fn end_rule(id: u16, polarity: RulePolarity) -> Self {
        let word = match polarity {
            RulePolarity::Deny => 0,
            RulePolarity::Hold => 1,
            RulePolarity::Advisory => 2,
        };
        Self {
            code: CODE_END_RULE,
            word,
            arg: id,
            mask: 0,
        }
    }
    fn sort_key(&self) -> (u8, u8, u64, bool, u64) {
        match self.code {
            CODE_ATOM_POS | CODE_ATOM_NEG => {
                (0, self.word, 0, self.code == CODE_ATOM_NEG, self.mask)
            }
            _ => {
                let bit = 1u64 << (self.arg % 64);
                let word = u8::try_from(self.arg / 64).unwrap_or(u8::MAX);
                (1, word, bit, self.code == CODE_RULE_NEG, bit)
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct Raw {
    pub magic: [u8; 4],
    pub version: u16,
    pub reserved: u16,
    pub atom_count: u16,
    pub rule_count: u16,
    pub op_count: Option<u32>,
    pub thresholds: Vec<(i32, i32)>,
    pub ops: Vec<RawOp>,
}

impl Raw {
    pub fn new(thresholds: Vec<(i32, i32)>, rule_count: u16, ops: Vec<RawOp>) -> Self {
        Self {
            magic: *b"CDM1",
            version: 1,
            reserved: 0,
            atom_count: u16::try_from(thresholds.len()).unwrap_or(u16::MAX),
            rule_count,
            op_count: None,
            thresholds,
            ops,
        }
    }

    pub fn bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.magic);
        out.extend_from_slice(&self.version.to_le_bytes());
        out.extend_from_slice(&self.reserved.to_le_bytes());
        out.extend_from_slice(&self.atom_count.to_le_bytes());
        out.extend_from_slice(&self.rule_count.to_le_bytes());
        let op_count = self
            .op_count
            .unwrap_or_else(|| u32::try_from(self.ops.len()).unwrap_or(u32::MAX));
        out.extend_from_slice(&op_count.to_le_bytes());
        for (neg, pos) in &self.thresholds {
            out.extend_from_slice(&neg.to_le_bytes());
            out.extend_from_slice(&pos.to_le_bytes());
        }
        for op in &self.ops {
            out.push(op.code);
            out.push(op.word);
            out.extend_from_slice(&op.arg.to_le_bytes());
            out.extend_from_slice(&op.mask.to_le_bytes());
        }
        out
    }
}

fn clause_ops(clause: &[Lit]) -> Vec<RawOp> {
    let mut atoms: BTreeMap<(u8, bool), u64> = BTreeMap::new();
    let mut rules: Vec<(u16, bool)> = Vec::new();
    for lit in clause {
        match *lit {
            Lit::Atom { id, negated } => {
                let word = u8::try_from(id / 64).unwrap_or(u8::MAX);
                *atoms.entry((word, negated)).or_default() |= 1u64 << (id % 64);
            }
            Lit::Rule { id, negated } => rules.push((id, negated)),
        }
    }
    rules.sort_unstable();
    rules.dedup();
    let mut ops: Vec<RawOp> = atoms
        .into_iter()
        .map(|((word, negated), mask)| RawOp::atoms(negated, word, mask))
        .collect();
    ops.extend(
        rules
            .into_iter()
            .map(|(id, negated)| RawOp::rule(negated, id)),
    );
    ops
}

/// Canonical encoding: merged atom masks, sorted literals, sorted and
/// deduplicated clauses.
pub fn encode(model: &Model) -> Vec<u8> {
    let mut ops = Vec::new();
    for (index, rule) in model.rules.iter().enumerate() {
        let mut clauses: Vec<Vec<RawOp>> = rule.clauses.iter().map(|c| clause_ops(c)).collect();
        clauses.sort_by(|a, b| {
            a.iter()
                .map(RawOp::sort_key)
                .cmp(b.iter().map(RawOp::sort_key))
        });
        clauses.dedup();
        for clause in clauses {
            ops.extend(clause);
            ops.push(RawOp::end_clause());
        }
        ops.push(RawOp::end_rule(
            u16::try_from(index).unwrap_or(u16::MAX),
            rule.polarity,
        ));
    }
    let rule_count = u16::try_from(model.rules.len()).unwrap_or(u16::MAX);
    Raw::new(model.thresholds.clone(), rule_count, ops).bytes()
}

pub fn tri_set<const W: usize>(trits: &[Trit]) -> TriSet<W> {
    let mut pos = [0u64; W];
    let mut neg = [0u64; W];
    for (i, trit) in trits.iter().enumerate() {
        match trit {
            Trit::True => pos[i / 64] |= 1 << (i % 64),
            Trit::False => neg[i / 64] |= 1 << (i % 64),
            Trit::Unknown => {}
        }
    }
    match TriSet::new(pos, neg, trits.len()) {
        Ok(set) => set,
        Err(error) => panic!("test trits form a valid set: {error:?}"),
    }
}

pub fn trits<const W: usize>(set: &TriSet<W>) -> Vec<Trit> {
    (0..set.live_bits()).filter_map(|i| set.get(i)).collect()
}

fn kleene_or(values: impl Iterator<Item = Trit>) -> Trit {
    let mut unknown = false;
    for value in values {
        match value {
            Trit::True => return Trit::True,
            Trit::Unknown => unknown = true,
            Trit::False => {}
        }
    }
    if unknown {
        Trit::Unknown
    } else {
        Trit::False
    }
}

fn kleene_and(values: impl Iterator<Item = Trit>) -> Trit {
    let mut unknown = false;
    for value in values {
        match value {
            Trit::False => return Trit::False,
            Trit::Unknown => unknown = true,
            Trit::True => {}
        }
    }
    if unknown {
        Trit::Unknown
    } else {
        Trit::True
    }
}

fn not(value: Trit) -> Trit {
    match value {
        Trit::True => Trit::False,
        Trit::False => Trit::True,
        Trit::Unknown => Trit::Unknown,
    }
}

fn rule_value(model: &Model, atoms: &[Trit], rule: usize, memo: &mut [Option<Trit>]) -> Trit {
    if let Some(value) = memo[rule] {
        return value;
    }
    let mut clause_values = Vec::new();
    for clause in &model.rules[rule].clauses {
        let mut literal_values = Vec::new();
        for lit in clause {
            let (value, negated) = match *lit {
                Lit::Atom { id, negated } => (atoms[usize::from(id)], negated),
                Lit::Rule { id, negated } => {
                    assert!(usize::from(id) < rule, "rule literals name earlier rules");
                    (rule_value(model, atoms, usize::from(id), memo), negated)
                }
            };
            literal_values.push(if negated { not(value) } else { value });
        }
        clause_values.push(kleene_or(literal_values.into_iter()));
    }
    let value = kleene_and(clause_values.into_iter());
    memo[rule] = Some(value);
    value
}

/// Naive recursive strong Kleene reference over the unencoded model.
pub fn reference(model: &Model, atoms: &[Trit]) -> (Vec<Trit>, Outcome) {
    let mut memo = vec![None; model.rules.len()];
    let values: Vec<Trit> = (0..model.rules.len())
        .map(|rule| rule_value(model, atoms, rule, &mut memo))
        .collect();
    let mut deny = false;
    let mut hold = false;
    for (rule, value) in model.rules.iter().zip(&values) {
        match (rule.polarity, value) {
            (RulePolarity::Deny, Trit::True) => deny = true,
            (RulePolarity::Deny, Trit::Unknown)
            | (RulePolarity::Hold, Trit::Unknown | Trit::True) => hold = true,
            _ => {}
        }
    }
    let outcome = if deny {
        Outcome::Deny
    } else if hold {
        Outcome::Hold
    } else {
        Outcome::Allow
    };
    (values, outcome)
}

/// Reference classification of one atom.
pub fn classify_reference(score: i32, tau_neg: i32, tau_pos: i32, attested: bool) -> Trit {
    if !attested {
        Trit::Unknown
    } else if score >= tau_pos {
        Trit::True
    } else if score < tau_neg {
        Trit::False
    } else {
        Trit::Unknown
    }
}

pub fn q_pairs(pairs: &[(i32, i32)]) -> Vec<(Q16_16, Q16_16)> {
    pairs
        .iter()
        .map(|(neg, pos)| (Q16_16::from_bits(*neg), Q16_16::from_bits(*pos)))
        .collect()
}

pub fn attested_words(bits: &[bool]) -> [u64; ATOM_WORDS] {
    let mut words = [0u64; ATOM_WORDS];
    for (i, set) in bits.iter().enumerate().take(MAX_ATOMS) {
        if *set {
            words[i / 64] |= 1 << (i % 64);
        }
    }
    words
}

pub fn single_atom_rule(polarity: RulePolarity, atom: u16) -> Rule {
    Rule {
        polarity,
        clauses: vec![vec![Lit::Atom {
            id: atom,
            negated: false,
        }]],
    }
}
