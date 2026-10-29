use crate::schedule::{OpCode, Schedule};
use crate::trit::{fill, TriSet};
use crate::{DagError, ATOM_WORDS, RULE_WORDS};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Outcome {
    Allow,
    Hold,
    Deny,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Evaluation {
    pub rules: TriSet<RULE_WORDS>,
    pub outcome: Outcome,
    pub work_ops: u32,
}

fn word(planes: &[u64], index: u8) -> u64 {
    planes.get(usize::from(index)).copied().unwrap_or(0)
}

impl Schedule<'_> {
    /// `granted_work` is the allowance already charged for this evaluation.
    /// `WorkExhausted` without evaluating when it is below `op_count()`.
    pub fn evaluate(
        &self,
        atoms: &TriSet<ATOM_WORDS>,
        granted_work: u32,
    ) -> Result<Evaluation, DagError> {
        if granted_work < self.op_count() {
            return Err(DagError::WorkExhausted);
        }
        if atoms.live_bits() != self.atom_count() {
            return Err(DagError::BadLength);
        }
        let mut atom_unknown = [0u64; ATOM_WORDS];
        for (index, slot) in atom_unknown.iter_mut().enumerate() {
            *slot = atoms.unknown_word(index);
        }
        let mut rule_pos = [0u64; RULE_WORDS];
        let mut rule_neg = [0u64; RULE_WORDS];
        let mut literal_true = false;
        let mut literal_unknown = false;
        let mut clause_false = false;
        let mut clause_unknown = false;
        for op in self.ops {
            match op.code {
                OpCode::AccAtomPos => {
                    literal_true |= word(atoms.pos_words(), op.word) & op.mask != 0;
                    literal_unknown |= word(&atom_unknown, op.word) & op.mask != 0;
                }
                OpCode::AccAtomNeg => {
                    literal_true |= word(atoms.neg_words(), op.word) & op.mask != 0;
                    literal_unknown |= word(&atom_unknown, op.word) & op.mask != 0;
                }
                OpCode::AccRulePos | OpCode::AccRuleNeg => {
                    let pos = word(&rule_pos, op.word);
                    let neg = word(&rule_neg, op.word);
                    let truth = if op.code == OpCode::AccRulePos {
                        pos
                    } else {
                        neg
                    };
                    literal_true |= truth & op.mask != 0;
                    literal_unknown |= !(pos | neg) & op.mask != 0;
                }
                OpCode::EndClause => {
                    clause_false |= !literal_true & !literal_unknown;
                    clause_unknown |= !literal_true & literal_unknown;
                    literal_true = false;
                    literal_unknown = false;
                }
                OpCode::EndRule => {
                    let index = usize::from(op.word);
                    let (pos, neg) = rule_pos
                        .get_mut(index)
                        .zip(rule_neg.get_mut(index))
                        .ok_or(DagError::RuleOutOfRange)?;
                    *pos |= op.mask & fill(!clause_false & !clause_unknown);
                    *neg |= op.mask & fill(clause_false);
                    clause_false = false;
                    clause_unknown = false;
                }
            }
        }
        let rules = TriSet::new(rule_pos, rule_neg, self.rule_count())?;
        let mut deny = false;
        let mut hold = false;
        let planes = self
            .meta
            .deny_rules
            .iter()
            .zip(&self.meta.hold_rules)
            .zip(rules.pos_words());
        for (index, ((deny_rules, hold_rules), pos)) in planes.enumerate() {
            let unknown = rules.unknown_word(index);
            deny |= pos & deny_rules != 0;
            hold |= (unknown & (deny_rules | hold_rules)) | (pos & hold_rules) != 0;
        }
        let outcome = if deny {
            Outcome::Deny
        } else if hold {
            Outcome::Hold
        } else {
            Outcome::Allow
        };
        Ok(Evaluation {
            rules,
            outcome,
            work_ops: self.op_count(),
        })
    }
}
