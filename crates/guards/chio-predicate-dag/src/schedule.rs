use crate::artifact;
use crate::thresholds::Thresholds;
use crate::trit::bit_position;
use crate::{DagError, ATOM_WORDS, MAX_SCHEDULE_OPS, RULE_WORDS};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RulePolarity {
    Deny,
    Hold,
    Advisory,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum OpCode {
    AccAtomPos,
    AccAtomNeg,
    AccRulePos,
    AccRuleNeg,
    EndClause,
    EndRule,
}

/// A validated op. Literal and `EndRule` ops address one plane word: `mask`
/// holds the atoms of that word, or the single bit of the rule.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct Op {
    pub(crate) code: OpCode,
    pub(crate) word: u8,
    pub(crate) mask: u64,
}

impl Op {
    pub(crate) const END_CLAUSE: Self = Self {
        code: OpCode::EndClause,
        word: 0,
        mask: 0,
    };
}

/// Counts and per-rule polarity planes of a validated schedule.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct Meta {
    pub(crate) atom_count: u16,
    pub(crate) rule_count: u16,
    pub(crate) op_count: u32,
    pub(crate) referenced_atoms: [u64; ATOM_WORDS],
    pub(crate) deny_rules: [u64; RULE_WORDS],
    pub(crate) hold_rules: [u64; RULE_WORDS],
}

impl Meta {
    pub(crate) const EMPTY: Self = Self {
        atom_count: 0,
        rule_count: 0,
        op_count: 0,
        referenced_atoms: [0; ATOM_WORDS],
        deny_rules: [0; RULE_WORDS],
        hold_rules: [0; RULE_WORDS],
    };
}

/// Caller-owned storage for one validated schedule. It holds a schedule only
/// after a successful `decode`; any failed `decode` leaves it invalid.
///
/// The storage holds `MAX_SCHEDULE_OPS` ops, about 1 MiB. Place it in a
/// `static` or a `Box`, never in a local on a thread stack.
#[derive(Debug)]
pub struct ScheduleStorage {
    ops: [Op; MAX_SCHEDULE_OPS],
    meta: Meta,
    validated: bool,
}

impl ScheduleStorage {
    pub const fn empty() -> Self {
        Self {
            ops: [Op::END_CLAUSE; MAX_SCHEDULE_OPS],
            meta: Meta::EMPTY,
            validated: false,
        }
    }

    /// Decodes and validates `chio.decision-model.v1` bytes. Fail closed.
    pub fn decode(&mut self, bytes: &[u8]) -> Result<Thresholds, DagError> {
        self.validated = false;
        let (meta, thresholds) = artifact::decode_into(bytes, &mut self.ops)?;
        self.meta = meta;
        self.validated = true;
        Ok(thresholds)
    }

    /// A view of the validated schedule, borrowed for one evaluation.
    pub fn schedule(&self) -> Result<Schedule<'_>, DagError> {
        if !self.validated {
            return Err(DagError::NotValidated);
        }
        let len = usize::try_from(self.meta.op_count).map_err(|_| DagError::NotValidated)?;
        let ops = self.ops.get(..len).ok_or(DagError::NotValidated)?;
        Ok(Schedule::new(ops, &self.meta))
    }
}

/// A validated, acyclic, canonical op stream.
#[derive(Clone, Copy, Debug)]
pub struct Schedule<'s> {
    pub(crate) ops: &'s [Op],
    pub(crate) meta: &'s Meta,
}

impl<'s> Schedule<'s> {
    pub(crate) fn new(ops: &'s [Op], meta: &'s Meta) -> Self {
        Self { ops, meta }
    }

    /// The fixed work of one evaluation, in ops.
    pub fn op_count(&self) -> u32 {
        self.meta.op_count
    }

    pub fn atom_count(&self) -> usize {
        usize::from(self.meta.atom_count)
    }

    pub fn rule_count(&self) -> usize {
        usize::from(self.meta.rule_count)
    }

    /// Atoms that at least one literal reads.
    pub fn referenced_atoms(&self) -> &[u64; ATOM_WORDS] {
        &self.meta.referenced_atoms
    }

    pub fn rule_polarity(&self, rule: usize) -> Option<RulePolarity> {
        if rule >= self.rule_count() {
            return None;
        }
        let (word, bit) = bit_position(rule)?;
        if self.meta.deny_rules.get(word)? & bit != 0 {
            Some(RulePolarity::Deny)
        } else if self.meta.hold_rules.get(word)? & bit != 0 {
            Some(RulePolarity::Hold)
        } else {
            Some(RulePolarity::Advisory)
        }
    }
}
