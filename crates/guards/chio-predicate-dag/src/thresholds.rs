use chio_fixed::Q16_16;

use crate::trit::{bit_position, fill, TriSet};
use crate::{DagError, ATOM_WORDS, MAX_ATOMS};

/// Per-atom `(tau_neg, tau_pos)` pairs with `tau_neg <= tau_pos`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Thresholds {
    pairs: [(Q16_16, Q16_16); MAX_ATOMS],
    len: usize,
}

impl Thresholds {
    pub fn new(pairs: &[(Q16_16, Q16_16)]) -> Result<Self, DagError> {
        if pairs.len() > MAX_ATOMS {
            return Err(DagError::AtomOutOfRange);
        }
        let mut stored = [(Q16_16::ZERO, Q16_16::ZERO); MAX_ATOMS];
        for (slot, (neg, pos)) in stored.iter_mut().zip(pairs) {
            if neg > pos {
                return Err(DagError::ThresholdOrder);
            }
            *slot = (*neg, *pos);
        }
        Ok(Self {
            pairs: stored,
            len: pairs.len(),
        })
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// `(tau_neg, tau_pos)` of `atom`.
    pub fn get(&self, atom: usize) -> Option<(Q16_16, Q16_16)> {
        if atom >= self.len {
            return None;
        }
        self.pairs.get(atom).copied()
    }

    pub(crate) fn pairs(&self) -> &[(Q16_16, Q16_16)] {
        self.pairs.get(..self.len).unwrap_or(&[])
    }
}

/// One score per atom and a bit per atom saying whether its score is attested.
#[derive(Clone, Copy, Debug)]
pub struct ScoreFrame<'a> {
    pub scores: &'a [Q16_16],
    pub attested: &'a [u64; ATOM_WORDS],
}

/// `s >= tau_pos` is `True`, `s < tau_neg` is `False`, anything else and every
/// unattested atom is `Unknown`.
pub fn classify(scores: &ScoreFrame<'_>, tau: &Thresholds) -> Result<TriSet<ATOM_WORDS>, DagError> {
    if scores.scores.len() != tau.len() {
        return Err(DagError::BadLength);
    }
    let mut pos = [0u64; ATOM_WORDS];
    let mut neg = [0u64; ATOM_WORDS];
    for (atom, (score, (tau_neg, tau_pos))) in scores.scores.iter().zip(tau.pairs()).enumerate() {
        let (word, bit) = bit_position(atom).ok_or(DagError::AtomOutOfRange)?;
        let attested = scores.attested.get(word).ok_or(DagError::AtomOutOfRange)? & bit;
        let known = fill(attested != 0);
        let (p, n) = pos
            .get_mut(word)
            .zip(neg.get_mut(word))
            .ok_or(DagError::AtomOutOfRange)?;
        *p |= bit & known & fill(score >= tau_pos);
        *n |= bit & known & fill(score < tau_neg);
    }
    TriSet::new(pos, neg, tau.len())
}
