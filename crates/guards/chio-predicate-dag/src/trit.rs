use crate::DagError;

/// A strong Kleene truth value.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Trit {
    True,
    False,
    Unknown,
}

/// Paired bit planes over `live_bits` positions: a set `pos` bit is `True`, a
/// set `neg` bit is `False`, neither is `Unknown`. Invariant: `pos & neg == 0`
/// and every bit at or above `live_bits` is zero in both planes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TriSet<const W: usize> {
    pos: [u64; W],
    neg: [u64; W],
    live_bits: usize,
}

impl<const W: usize> TriSet<W> {
    pub fn new(pos: [u64; W], neg: [u64; W], live_bits: usize) -> Result<Self, DagError> {
        if W.checked_mul(64)
            .is_none_or(|capacity| live_bits > capacity)
        {
            return Err(DagError::BadLength);
        }
        for (word, (p, n)) in pos.iter().zip(neg.iter()).enumerate() {
            if p & n != 0 {
                return Err(DagError::PlaneOverlap);
            }
            if (p | n) & !live_mask(word, live_bits) != 0 {
                return Err(DagError::PaddingNotZero);
            }
        }
        Ok(Self {
            pos,
            neg,
            live_bits,
        })
    }

    pub fn get(&self, i: usize) -> Option<Trit> {
        if i >= self.live_bits {
            return None;
        }
        let (word, bit) = bit_position(i)?;
        let p = self.pos.get(word)? & bit;
        let n = self.neg.get(word)? & bit;
        Some(if p != 0 {
            Trit::True
        } else if n != 0 {
            Trit::False
        } else {
            Trit::Unknown
        })
    }

    pub fn live_bits(&self) -> usize {
        self.live_bits
    }

    pub fn pos_words(&self) -> &[u64; W] {
        &self.pos
    }

    pub fn neg_words(&self) -> &[u64; W] {
        &self.neg
    }

    /// Live positions of `word` that are neither true nor false.
    pub(crate) fn unknown_word(&self, word: usize) -> u64 {
        let p = self.pos.get(word).copied().unwrap_or(0);
        let n = self.neg.get(word).copied().unwrap_or(0);
        !(p | n) & live_mask(word, self.live_bits)
    }
}

/// The bits of `word` whose positions lie below `live_bits`.
pub(crate) fn live_mask(word: usize, live_bits: usize) -> u64 {
    let Some(start) = word.checked_mul(64) else {
        return 0;
    };
    match live_bits.checked_sub(start) {
        None | Some(0) => 0,
        Some(n) if n >= 64 => u64::MAX,
        Some(n) => u32::try_from(n)
            .ok()
            .and_then(|n| 1u64.checked_shl(n))
            .and_then(|b| b.checked_sub(1))
            .unwrap_or(0),
    }
}

/// Word index and single-bit mask of position `i`.
pub(crate) fn bit_position(i: usize) -> Option<(usize, u64)> {
    let word = i.checked_div(64)?;
    let bit = u32::try_from(i.checked_rem(64)?).ok()?;
    Some((word, 1u64.checked_shl(bit)?))
}

/// `0` for `false` and all ones for `true`. The only wrapping operation in the
/// crate: `0 - 1` wraps to `u64::MAX` by design.
pub(crate) fn fill(b: bool) -> u64 {
    0u64.wrapping_sub(u64::from(b))
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use super::{fill, live_mask};

    #[test]
    fn fill_pins_both_values() {
        assert_eq!(fill(false), 0);
        assert_eq!(fill(true), u64::MAX);
    }

    #[test]
    fn live_mask_covers_partial_and_full_words() {
        assert_eq!(live_mask(0, 0), 0);
        assert_eq!(live_mask(0, 1), 1);
        assert_eq!(live_mask(0, 64), u64::MAX);
        assert_eq!(live_mask(1, 64), 0);
        assert_eq!(live_mask(1, 65), 1);
        assert_eq!(live_mask(8, 537), (1u64 << 25) - 1);
        assert_eq!(live_mask(15, 1024), u64::MAX);
    }
}
