use core::cmp::Ordering;

/// Orders `a / b` against `c / d` by exact cross-multiplication in `u64`.
///
/// `None` when either denominator is zero. Equal ratios compare `Equal`
/// regardless of representation, so `1/2` and `2/4` tie.
pub fn ratio_cmp(a: u32, b: u32, c: u32, d: u32) -> Option<Ordering> {
    if b == 0 || d == 0 {
        return None;
    }
    let lhs = u64::from(a).checked_mul(u64::from(d))?;
    let rhs = u64::from(c).checked_mul(u64::from(b))?;
    Some(lhs.cmp(&rhs))
}
