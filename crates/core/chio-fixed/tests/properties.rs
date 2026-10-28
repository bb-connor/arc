use chio_fixed::{checked_dot, checked_sum, ratio_cmp, Q16_16};
use proptest::prelude::*;

fn floor_mul_reference(a: i32, b: i32) -> Option<i32> {
    let product = i128::from(a) * i128::from(b);
    i32::try_from(product.div_euclid(1 << 16)).ok()
}

fn floor_div_reference(a: i32, b: i32) -> Option<i32> {
    if b == 0 {
        return None;
    }
    let numerator = i128::from(a) << 16;
    let denominator = i128::from(b);
    let quotient = numerator / denominator;
    let floored = if numerator % denominator != 0 && ((numerator < 0) != (denominator < 0)) {
        quotient - 1
    } else {
        quotient
    };
    i32::try_from(floored).ok()
}

fn ratio_reference(a: u32, b: u32, c: u32, d: u32) -> Option<core::cmp::Ordering> {
    if b == 0 || d == 0 {
        return None;
    }
    Some((u128::from(a) * u128::from(d)).cmp(&(u128::from(c) * u128::from(b))))
}

fn bits(values: &[i32]) -> Vec<Q16_16> {
    values.iter().copied().map(Q16_16::from_bits).collect()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4096))]

    #[test]
    fn checked_mul_matches_i128_floor(a in any::<i32>(), b in any::<i32>()) {
        let got = Q16_16::from_bits(a).checked_mul(Q16_16::from_bits(b)).map(Q16_16::to_bits);
        prop_assert_eq!(got, floor_mul_reference(a, b));
    }

    #[test]
    fn checked_mul_matches_i128_floor_near_one(a in -(1i32 << 20)..(1i32 << 20), b in -(1i32 << 20)..(1i32 << 20)) {
        let got = Q16_16::from_bits(a).checked_mul(Q16_16::from_bits(b)).map(Q16_16::to_bits);
        prop_assert_eq!(got, floor_mul_reference(a, b));
    }

    #[test]
    fn checked_div_matches_i128_floor(a in any::<i32>(), b in any::<i32>()) {
        let got = Q16_16::from_bits(a).checked_div(Q16_16::from_bits(b)).map(Q16_16::to_bits);
        prop_assert_eq!(got, floor_div_reference(a, b));
    }

    #[test]
    fn checked_div_matches_i128_floor_small_divisor(a in any::<i32>(), b in -(1i32 << 18)..(1i32 << 18)) {
        let got = Q16_16::from_bits(a).checked_div(Q16_16::from_bits(b)).map(Q16_16::to_bits);
        prop_assert_eq!(got, floor_div_reference(a, b));
    }

    #[test]
    fn checked_add_sub_neg_match_i64(a in any::<i32>(), b in any::<i32>()) {
        let (x, y) = (Q16_16::from_bits(a), Q16_16::from_bits(b));
        let sum = i32::try_from(i64::from(a) + i64::from(b)).ok();
        let difference = i32::try_from(i64::from(a) - i64::from(b)).ok();
        let negation = i32::try_from(-i64::from(a)).ok();
        prop_assert_eq!(x.checked_add(y).map(Q16_16::to_bits), sum);
        prop_assert_eq!(x.checked_sub(y).map(Q16_16::to_bits), difference);
        prop_assert_eq!(x.checked_neg().map(Q16_16::to_bits), negation);
    }

    #[test]
    fn floor_to_int_is_floor_of_exact_value(a in any::<i32>()) {
        let expected = i64::from(a).div_euclid(1 << 16);
        prop_assert_eq!(i64::from(Q16_16::from_bits(a).floor_to_int()), expected);
    }

    #[test]
    fn from_int_round_trips_through_floor(v in any::<i16>()) {
        let value = Q16_16::from_int(v);
        prop_assert_eq!(i64::from(value.to_bits()), i64::from(v) << 16);
        prop_assert_eq!(value.floor_to_int(), v);
    }

    #[test]
    fn from_bps_is_floor_and_bounded(bps in any::<u16>()) {
        let expected = if bps <= 10_000 {
            i32::try_from(u64::from(bps) * 65_536 / 10_000).ok()
        } else {
            None
        };
        prop_assert_eq!(Q16_16::from_bps(bps).map(Q16_16::to_bits), expected);
    }

    #[test]
    fn checked_sum_is_none_iff_a_prefix_overflows(terms in proptest::collection::vec(any::<i32>(), 0..12)) {
        let mut acc: i64 = 0;
        let mut prefix_overflow = false;
        for term in &terms {
            acc += i64::from(*term);
            if i32::try_from(acc).is_err() {
                prefix_overflow = true;
                break;
            }
        }
        let got = checked_sum(&bits(&terms)).map(Q16_16::to_bits);
        if prefix_overflow {
            prop_assert_eq!(got, None);
        } else {
            prop_assert_eq!(got, i32::try_from(acc).ok());
        }
    }

    #[test]
    fn checked_sum_small_terms_never_overflow(terms in proptest::collection::vec(-(1i32 << 20)..(1i32 << 20), 0..64)) {
        let exact: i64 = terms.iter().copied().map(i64::from).sum();
        prop_assert_eq!(checked_sum(&bits(&terms)).map(Q16_16::to_bits), i32::try_from(exact).ok());
    }

    #[test]
    fn checked_dot_matches_left_to_right_reference(
        pairs in proptest::collection::vec((any::<i32>(), any::<i32>()), 0..8)
    ) {
        let (a, b): (Vec<i32>, Vec<i32>) = pairs.iter().copied().unzip();
        let mut expected = Some(0i32);
        for (x, y) in pairs {
            expected = match (expected, floor_mul_reference(x, y)) {
                (Some(acc), Some(product)) => acc.checked_add(product),
                _ => None,
            };
            if expected.is_none() {
                break;
            }
        }
        prop_assert_eq!(checked_dot(&bits(&a), &bits(&b)).map(Q16_16::to_bits), expected);
    }

    #[test]
    fn checked_dot_rejects_length_mismatch(
        a in proptest::collection::vec(any::<i32>(), 0..8),
        b in proptest::collection::vec(any::<i32>(), 0..8),
    ) {
        prop_assume!(a.len() != b.len());
        prop_assert_eq!(checked_dot(&bits(&a), &bits(&b)), None);
    }

    #[test]
    fn ratio_cmp_matches_u128_exact(a in any::<u32>(), b in any::<u32>(), c in any::<u32>(), d in any::<u32>()) {
        prop_assert_eq!(ratio_cmp(a, b, c, d), ratio_reference(a, b, c, d));
    }

    #[test]
    fn ratio_cmp_matches_u128_exact_small(a in 0u32..64, b in 0u32..64, c in 0u32..64, d in 0u32..64) {
        prop_assert_eq!(ratio_cmp(a, b, c, d), ratio_reference(a, b, c, d));
    }

    #[test]
    fn ratio_cmp_is_antisymmetric_and_reflexive(a in any::<u32>(), b in 1u32.., c in any::<u32>(), d in 1u32..) {
        prop_assert_eq!(ratio_cmp(a, b, c, d), ratio_cmp(c, d, a, b).map(core::cmp::Ordering::reverse));
        prop_assert_eq!(ratio_cmp(a, b, a, b), Some(core::cmp::Ordering::Equal));
    }

    #[test]
    fn ratio_cmp_is_transitive(
        a in 0u32..1_000, b in 1u32..1_000,
        c in 0u32..1_000, d in 1u32..1_000,
        e in 0u32..1_000, f in 1u32..1_000,
    ) {
        use core::cmp::Ordering::{Greater, Less};
        let ab_cd = ratio_cmp(a, b, c, d);
        let cd_ef = ratio_cmp(c, d, e, f);
        let ab_ef = ratio_cmp(a, b, e, f);
        if ab_cd != Some(Greater) && cd_ef != Some(Greater) {
            prop_assert_ne!(ab_ef, Some(Greater));
        }
        if ab_cd == Some(Less) && cd_ef == Some(Less) {
            prop_assert_eq!(ab_ef, Some(Less));
        }
    }
}
