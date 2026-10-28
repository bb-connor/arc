use core::cmp::Ordering;

use chio_fixed::Q16_16;

use crate::schedule::{Meta, Op, OpCode};
use crate::thresholds::Thresholds;
use crate::trit::{bit_position, live_mask};
use crate::{
    DagError, ARTIFACT_MAGIC, ARTIFACT_VERSION, ATOM_WORDS, MAX_ATOMS, MAX_CLAUSES,
    MAX_CLAUSES_PER_RULE, MAX_LITERALS_PER_CLAUSE, MAX_RULES, MAX_SCHEDULE_OPS,
};

const HEADER_LEN: usize = 16;
const THRESHOLD_LEN: usize = 8;
const OP_LEN: usize = 12;

const CODE_ATOM_POS: u8 = 1;
const CODE_ATOM_NEG: u8 = 2;
const CODE_RULE_POS: u8 = 3;
const CODE_RULE_NEG: u8 = 4;
const CODE_END_CLAUSE: u8 = 5;
const CODE_END_RULE: u8 = 6;

const POLARITY_DENY: u8 = 0;
const POLARITY_HOLD: u8 = 1;
const POLARITY_ADVISORY: u8 = 2;

/// Ordering key of a literal op: atoms before rules, then word, then the
/// rule bit (zero for atoms), then positive before negated.
fn literal_key(op: &Op) -> (u8, u8, u64, bool) {
    match op.code {
        OpCode::AccAtomPos => (0, op.word, 0, false),
        OpCode::AccAtomNeg => (0, op.word, 0, true),
        OpCode::AccRulePos => (1, op.word, op.mask, false),
        OpCode::AccRuleNeg => (1, op.word, op.mask, true),
        OpCode::EndClause | OpCode::EndRule => (2, 0, 0, false),
    }
}

fn clause_key(op: &Op) -> ((u8, u8, u64, bool), u64) {
    (literal_key(op), op.mask)
}

fn read<const N: usize>(bytes: &[u8], at: usize) -> Result<[u8; N], DagError> {
    let end = at.checked_add(N).ok_or(DagError::BadLength)?;
    bytes
        .get(at..end)
        .and_then(|slice| <[u8; N]>::try_from(slice).ok())
        .ok_or(DagError::BadLength)
}

/// Decodes and validates an artifact into `ops`. Fail closed: on error the
/// contents of `ops` are unspecified and must not be evaluated.
pub(crate) fn decode_into(bytes: &[u8], ops: &mut [Op]) -> Result<(Meta, Thresholds), DagError> {
    if bytes.len() < HEADER_LEN {
        return Err(DagError::BadLength);
    }
    if &read::<4>(bytes, 0)? != ARTIFACT_MAGIC
        || u16::from_le_bytes(read(bytes, 4)?) != ARTIFACT_VERSION
    {
        return Err(DagError::BadMagic);
    }
    if u16::from_le_bytes(read(bytes, 6)?) != 0 {
        return Err(DagError::PaddingNotZero);
    }
    let atom_count = u16::from_le_bytes(read(bytes, 8)?);
    let rule_count = u16::from_le_bytes(read(bytes, 10)?);
    let op_count = u32::from_le_bytes(read(bytes, 12)?);
    let atoms = usize::from(atom_count);
    let rules = usize::from(rule_count);
    if atoms == 0 || atoms > MAX_ATOMS {
        return Err(DagError::AtomOutOfRange);
    }
    if rules == 0 || rules > MAX_RULES {
        return Err(DagError::RuleOutOfRange);
    }
    let op_len = usize::try_from(op_count).map_err(|_| DagError::TooManyOps)?;
    if op_len > MAX_SCHEDULE_OPS || op_len > ops.len() {
        return Err(DagError::TooManyOps);
    }
    let threshold_bytes = atoms
        .checked_mul(THRESHOLD_LEN)
        .ok_or(DagError::BadLength)?;
    let ops_at = HEADER_LEN
        .checked_add(threshold_bytes)
        .ok_or(DagError::BadLength)?;
    let expected = op_len
        .checked_mul(OP_LEN)
        .and_then(|n| n.checked_add(ops_at))
        .ok_or(DagError::BadLength)?;
    if bytes.len() != expected {
        return Err(DagError::BadLength);
    }

    let mut pairs = [(Q16_16::ZERO, Q16_16::ZERO); MAX_ATOMS];
    for (atom, pair) in pairs.iter_mut().take(atoms).enumerate() {
        let at = atom
            .checked_mul(THRESHOLD_LEN)
            .and_then(|n| n.checked_add(HEADER_LEN))
            .ok_or(DagError::BadLength)?;
        let neg = i32::from_le_bytes(read(bytes, at)?);
        let pos = i32::from_le_bytes(read(bytes, at.checked_add(4).ok_or(DagError::BadLength)?)?);
        *pair = (Q16_16::from_bits(neg), Q16_16::from_bits(pos));
    }
    let thresholds = Thresholds::new(pairs.get(..atoms).ok_or(DagError::BadLength)?)?;

    let mut meta = Meta::EMPTY;
    meta.atom_count = atom_count;
    meta.rule_count = rule_count;
    meta.op_count = op_count;

    let mut state = Validator::default();
    let encoded = bytes.get(ops_at..).ok_or(DagError::BadLength)?;
    for (index, raw) in encoded.chunks_exact(OP_LEN).enumerate() {
        let op = state.step(raw, index, atoms, rules, ops, &mut meta)?;
        *ops.get_mut(index).ok_or(DagError::TooManyOps)? = op;
    }
    if state.rules_done != rules || state.clause_literals != 0 || state.clause_start != op_len {
        return Err(DagError::ClauseNotCanonical);
    }
    Ok((meta, thresholds))
}

#[derive(Default)]
struct Validator {
    rules_done: usize,
    clause_start: usize,
    clause_literals: usize,
    last_literal: Option<(u8, u8, u64, bool)>,
    previous_clause: Option<(usize, usize)>,
    rule_clauses: usize,
    total_clauses: usize,
}

impl Validator {
    fn step(
        &mut self,
        raw: &[u8],
        index: usize,
        atoms: usize,
        rules: usize,
        ops: &[Op],
        meta: &mut Meta,
    ) -> Result<Op, DagError> {
        let code = *raw.first().ok_or(DagError::BadLength)?;
        let word = *raw.get(1).ok_or(DagError::BadLength)?;
        let arg = u16::from_le_bytes(read(raw, 2)?);
        let mask = u64::from_le_bytes(read(raw, 4)?);
        match code {
            CODE_ATOM_POS | CODE_ATOM_NEG => {
                if arg != 0 {
                    return Err(DagError::PaddingNotZero);
                }
                let w = usize::from(word);
                if w >= ATOM_WORDS || live_mask(w, atoms) == 0 {
                    return Err(DagError::AtomOutOfRange);
                }
                if mask == 0 {
                    return Err(DagError::ClauseNotCanonical);
                }
                if mask & !live_mask(w, atoms) != 0 {
                    return Err(DagError::AtomOutOfRange);
                }
                let op = Op {
                    code: if code == CODE_ATOM_POS {
                        OpCode::AccAtomPos
                    } else {
                        OpCode::AccAtomNeg
                    },
                    word,
                    mask,
                };
                let literals =
                    usize::try_from(mask.count_ones()).map_err(|_| DagError::BadLength)?;
                self.literal(op, literals, rules)?;
                let referenced = meta
                    .referenced_atoms
                    .get_mut(w)
                    .ok_or(DagError::AtomOutOfRange)?;
                *referenced |= mask;
                Ok(op)
            }
            CODE_RULE_POS | CODE_RULE_NEG => {
                if word != 0 || mask != 0 {
                    return Err(DagError::PaddingNotZero);
                }
                let rule = usize::from(arg);
                if rule >= rules {
                    return Err(DagError::RuleOutOfRange);
                }
                if rule >= self.rules_done {
                    return Err(DagError::Cycle);
                }
                let (w, bit) = bit_position(rule).ok_or(DagError::RuleOutOfRange)?;
                let op = Op {
                    code: if code == CODE_RULE_POS {
                        OpCode::AccRulePos
                    } else {
                        OpCode::AccRuleNeg
                    },
                    word: u8::try_from(w).map_err(|_| DagError::RuleOutOfRange)?,
                    mask: bit,
                };
                self.literal(op, 1, rules)?;
                Ok(op)
            }
            CODE_END_CLAUSE => {
                if word != 0 || arg != 0 || mask != 0 {
                    return Err(DagError::PaddingNotZero);
                }
                if self.clause_literals == 0 {
                    return Err(DagError::ClauseNotCanonical);
                }
                let current = ops
                    .get(self.clause_start..index)
                    .ok_or(DagError::BadLength)?;
                if let Some((start, end)) = self.previous_clause {
                    let previous = ops.get(start..end).ok_or(DagError::BadLength)?;
                    match previous
                        .iter()
                        .map(clause_key)
                        .cmp(current.iter().map(clause_key))
                    {
                        Ordering::Less => {}
                        Ordering::Equal => return Err(DagError::DuplicateClause),
                        Ordering::Greater => return Err(DagError::ClauseNotCanonical),
                    }
                }
                self.rule_clauses = self
                    .rule_clauses
                    .checked_add(1)
                    .ok_or(DagError::TooManyClauses)?;
                self.total_clauses = self
                    .total_clauses
                    .checked_add(1)
                    .ok_or(DagError::TooManyClauses)?;
                if self.rule_clauses > MAX_CLAUSES_PER_RULE || self.total_clauses > MAX_CLAUSES {
                    return Err(DagError::TooManyClauses);
                }
                self.previous_clause = Some((self.clause_start, index));
                self.clause_start = index.checked_add(1).ok_or(DagError::TooManyOps)?;
                self.clause_literals = 0;
                self.last_literal = None;
                Ok(Op::END_CLAUSE)
            }
            CODE_END_RULE => {
                if mask != 0 {
                    return Err(DagError::PaddingNotZero);
                }
                let rule = usize::from(arg);
                if rule >= rules {
                    return Err(DagError::RuleOutOfRange);
                }
                if rule != self.rules_done || self.clause_literals != 0 || self.rule_clauses == 0 {
                    return Err(DagError::ClauseNotCanonical);
                }
                let (w, bit) = bit_position(rule).ok_or(DagError::RuleOutOfRange)?;
                match word {
                    POLARITY_DENY => {
                        *meta.deny_rules.get_mut(w).ok_or(DagError::RuleOutOfRange)? |= bit;
                    }
                    POLARITY_HOLD => {
                        *meta.hold_rules.get_mut(w).ok_or(DagError::RuleOutOfRange)? |= bit;
                    }
                    POLARITY_ADVISORY => {}
                    _ => return Err(DagError::ClauseNotCanonical),
                }
                self.rules_done = self
                    .rules_done
                    .checked_add(1)
                    .ok_or(DagError::RuleOutOfRange)?;
                self.rule_clauses = 0;
                self.previous_clause = None;
                self.clause_start = index.checked_add(1).ok_or(DagError::TooManyOps)?;
                Ok(Op {
                    code: OpCode::EndRule,
                    word: u8::try_from(w).map_err(|_| DagError::RuleOutOfRange)?,
                    mask: bit,
                })
            }
            _ => Err(DagError::ClauseNotCanonical),
        }
    }

    fn literal(&mut self, op: Op, literals: usize, rules: usize) -> Result<(), DagError> {
        if self.rules_done >= rules {
            return Err(DagError::ClauseNotCanonical);
        }
        let key = literal_key(&op);
        if self.last_literal.is_some_and(|last| last >= key) {
            return Err(DagError::ClauseNotCanonical);
        }
        self.last_literal = Some(key);
        self.clause_literals = self
            .clause_literals
            .checked_add(literals)
            .ok_or(DagError::ClauseNotCanonical)?;
        if self.clause_literals > MAX_LITERALS_PER_CLAUSE {
            return Err(DagError::ClauseNotCanonical);
        }
        Ok(())
    }
}
