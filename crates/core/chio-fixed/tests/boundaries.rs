use core::cmp::Ordering;

use chio_fixed::{checked_dot, checked_sum, ratio_cmp, Q16_16};

const HALF: Q16_16 = Q16_16::from_bits(0x0000_8000);
const EPSILON: Q16_16 = Q16_16::from_bits(1);
const NEG_EPSILON: Q16_16 = Q16_16::from_bits(-1);

#[test]
fn constants_pin_bit_patterns() {
    assert_eq!(Q16_16::FRAC_BITS, 16);
    assert_eq!(Q16_16::ZERO.to_bits(), 0);
    assert_eq!(Q16_16::ONE.to_bits(), 0x0001_0000);
    assert_eq!(Q16_16::MAX.to_bits(), i32::MAX);
    assert_eq!(Q16_16::MIN.to_bits(), i32::MIN);
    assert_eq!(Q16_16::from_int(1), Q16_16::ONE);
    assert_eq!(Q16_16::from_int(0), Q16_16::ZERO);
}

#[test]
fn from_int_covers_the_full_i16_range() {
    assert_eq!(Q16_16::from_int(i16::MAX).to_bits(), 0x7FFF_0000);
    assert_eq!(Q16_16::from_int(i16::MIN).to_bits(), i32::MIN);
    assert_eq!(Q16_16::from_int(-1).to_bits(), -0x0001_0000);
}

#[test]
fn from_bps_floors_and_rejects_above_one() {
    assert_eq!(Q16_16::from_bps(0), Some(Q16_16::ZERO));
    assert_eq!(Q16_16::from_bps(10_000), Some(Q16_16::ONE));
    assert_eq!(Q16_16::from_bps(5_000), Some(HALF));
    assert_eq!(Q16_16::from_bps(1), Some(Q16_16::from_bits(6)));
    assert_eq!(Q16_16::from_bps(9_999), Some(Q16_16::from_bits(65_529)));
    assert_eq!(Q16_16::from_bps(10_001), None);
    assert_eq!(Q16_16::from_bps(u16::MAX), None);
}

#[test]
fn checked_add_refuses_at_both_boundaries() {
    assert_eq!(Q16_16::MAX.checked_add(Q16_16::ZERO), Some(Q16_16::MAX));
    assert_eq!(Q16_16::MAX.checked_add(EPSILON), None);
    assert_eq!(Q16_16::MIN.checked_add(NEG_EPSILON), None);
    assert_eq!(Q16_16::MIN.checked_add(Q16_16::MAX), Some(NEG_EPSILON));
}

#[test]
fn checked_sub_refuses_at_both_boundaries() {
    assert_eq!(Q16_16::MIN.checked_sub(EPSILON), None);
    assert_eq!(Q16_16::MAX.checked_sub(NEG_EPSILON), None);
    assert_eq!(Q16_16::ZERO.checked_sub(Q16_16::MIN), None);
    assert_eq!(
        Q16_16::ZERO.checked_sub(Q16_16::MAX),
        Some(Q16_16::from_bits(-i32::MAX))
    );
}

#[test]
fn checked_neg_refuses_min_only() {
    assert_eq!(Q16_16::MIN.checked_neg(), None);
    assert_eq!(
        Q16_16::MAX.checked_neg(),
        Some(Q16_16::from_bits(-i32::MAX))
    );
    assert_eq!(Q16_16::ZERO.checked_neg(), Some(Q16_16::ZERO));
}

#[test]
fn checked_mul_refuses_out_of_range_products() {
    assert_eq!(Q16_16::MAX.checked_mul(Q16_16::ONE), Some(Q16_16::MAX));
    assert_eq!(Q16_16::MIN.checked_mul(Q16_16::ONE), Some(Q16_16::MIN));
    assert_eq!(Q16_16::MAX.checked_mul(Q16_16::from_int(2)), None);
    assert_eq!(Q16_16::MIN.checked_mul(Q16_16::from_int(-1)), None);
    assert_eq!(Q16_16::MIN.checked_mul(Q16_16::MIN), None);
    assert_eq!(
        Q16_16::from_int(181).checked_mul(Q16_16::from_int(181)),
        Some(Q16_16::from_int(32_761))
    );
    assert_eq!(
        Q16_16::from_int(182).checked_mul(Q16_16::from_int(181)),
        None
    );
    assert_eq!(
        Q16_16::from_int(-256).checked_mul(Q16_16::from_int(128)),
        Some(Q16_16::MIN)
    );
    assert_eq!(
        Q16_16::from_int(256).checked_mul(Q16_16::from_int(128)),
        None
    );
}

#[test]
fn checked_mul_floors_toward_negative_infinity() {
    assert_eq!(EPSILON.checked_mul(HALF), Some(Q16_16::ZERO));
    assert_eq!(NEG_EPSILON.checked_mul(HALF), Some(NEG_EPSILON));
    assert_eq!(NEG_EPSILON.checked_mul(EPSILON), Some(NEG_EPSILON));
    assert_eq!(EPSILON.checked_mul(EPSILON), Some(Q16_16::ZERO));
    assert_eq!(
        Q16_16::from_bits(-3).checked_mul(HALF),
        Some(Q16_16::from_bits(-2))
    );
    assert_eq!(
        Q16_16::from_bits(3).checked_mul(HALF),
        Some(Q16_16::from_bits(1))
    );
}

#[test]
fn checked_div_refuses_zero_and_out_of_range_quotients() {
    assert_eq!(Q16_16::ONE.checked_div(Q16_16::ZERO), None);
    assert_eq!(Q16_16::ZERO.checked_div(Q16_16::ZERO), None);
    assert_eq!(Q16_16::MIN.checked_div(Q16_16::from_int(-1)), None);
    assert_eq!(Q16_16::MAX.checked_div(HALF), None);
    assert_eq!(Q16_16::ONE.checked_div(EPSILON), None);
    assert_eq!(Q16_16::MIN.checked_div(Q16_16::ONE), Some(Q16_16::MIN));
    assert_eq!(Q16_16::MAX.checked_div(Q16_16::ONE), Some(Q16_16::MAX));
    assert_eq!(
        Q16_16::from_int(-1).checked_div(HALF),
        Some(Q16_16::from_int(-2))
    );
}

#[test]
fn checked_div_floors_toward_negative_infinity() {
    let three = Q16_16::from_int(3);
    assert_eq!(
        Q16_16::ONE.checked_div(three),
        Some(Q16_16::from_bits(21_845))
    );
    assert_eq!(
        Q16_16::from_int(-1).checked_div(three),
        Some(Q16_16::from_bits(-21_846))
    );
    assert_eq!(
        Q16_16::ONE.checked_div(Q16_16::from_int(-3)),
        Some(Q16_16::from_bits(-21_846))
    );
    assert_eq!(
        Q16_16::from_int(-1).checked_div(Q16_16::from_int(-3)),
        Some(Q16_16::from_bits(21_845))
    );
    assert_eq!(NEG_EPSILON.checked_div(Q16_16::MAX), Some(NEG_EPSILON));
    assert_eq!(EPSILON.checked_div(Q16_16::MAX), Some(Q16_16::ZERO));
}

#[test]
fn checked_div_floors_signed_quotients_for_both_denominator_signs() {
    let int = Q16_16::from_int;
    assert_eq!(
        int(7).checked_div(int(2)),
        Some(Q16_16::from_bits(0x0003_8000))
    );
    assert_eq!(
        int(-7).checked_div(int(2)),
        Some(Q16_16::from_bits(-0x0003_8000))
    );
    assert_eq!(
        int(7).checked_div(int(-2)),
        Some(Q16_16::from_bits(-0x0003_8000))
    );
    assert_eq!(
        int(-7).checked_div(int(-2)),
        Some(Q16_16::from_bits(0x0003_8000))
    );
    assert_eq!(int(-6).checked_div(int(3)), Some(int(-2)));
    assert_eq!(int(6).checked_div(int(-3)), Some(int(-2)));
    assert_eq!(int(-6).checked_div(int(-3)), Some(int(2)));

    let seven = Q16_16::from_bits(7);
    let two = Q16_16::from_bits(0x0002_0000);
    let neg_two = Q16_16::from_bits(-0x0002_0000);
    assert_eq!(seven.checked_div(two), Some(Q16_16::from_bits(3)));
    assert_eq!(
        Q16_16::from_bits(-7).checked_div(two),
        Some(Q16_16::from_bits(-4))
    );
    assert_eq!(seven.checked_div(neg_two), Some(Q16_16::from_bits(-4)));
    assert_eq!(
        Q16_16::from_bits(-7).checked_div(neg_two),
        Some(Q16_16::from_bits(3))
    );
    assert_eq!(
        Q16_16::from_bits(-6).checked_div(two),
        Some(Q16_16::from_bits(-3))
    );
    assert_eq!(
        Q16_16::from_bits(6).checked_div(neg_two),
        Some(Q16_16::from_bits(-3))
    );
}

#[test]
fn floor_to_int_floors_negative_fractions() {
    assert_eq!(NEG_EPSILON.floor_to_int(), -1);
    assert_eq!(EPSILON.floor_to_int(), 0);
    assert_eq!(Q16_16::from_bits(-0x0001_0000).floor_to_int(), -1);
    assert_eq!(Q16_16::from_bits(-0x0001_0001).floor_to_int(), -2);
    assert_eq!(Q16_16::from_bits(0x0001_FFFF).floor_to_int(), 1);
    assert_eq!(Q16_16::MAX.floor_to_int(), i16::MAX);
    assert_eq!(Q16_16::MIN.floor_to_int(), i16::MIN);
}

#[test]
fn checked_sum_is_left_to_right_and_refuses_prefix_overflow() {
    assert_eq!(checked_sum(&[]), Some(Q16_16::ZERO));
    assert_eq!(checked_sum(&[Q16_16::MAX]), Some(Q16_16::MAX));
    assert_eq!(checked_sum(&[Q16_16::MAX, EPSILON, NEG_EPSILON]), None);
    assert_eq!(
        checked_sum(&[Q16_16::MAX, NEG_EPSILON, EPSILON]),
        Some(Q16_16::MAX)
    );
    assert_eq!(checked_sum(&[Q16_16::MIN, NEG_EPSILON, Q16_16::ONE]), None);
}

#[test]
fn checked_dot_refuses_mismatch_and_product_or_sum_overflow() {
    assert_eq!(checked_dot(&[], &[]), Some(Q16_16::ZERO));
    assert_eq!(checked_dot(&[Q16_16::ONE], &[]), None);
    assert_eq!(checked_dot(&[], &[Q16_16::ONE]), None);
    assert_eq!(
        checked_dot(
            &[Q16_16::ONE, HALF],
            &[Q16_16::from_int(3), Q16_16::from_int(4)]
        ),
        Some(Q16_16::from_int(5))
    );
    assert_eq!(checked_dot(&[Q16_16::MAX], &[Q16_16::from_int(2)]), None);
    assert_eq!(
        checked_dot(&[Q16_16::MAX, Q16_16::ONE], &[Q16_16::ONE, EPSILON]),
        None
    );
    assert_eq!(
        checked_dot(&[NEG_EPSILON, EPSILON], &[HALF, HALF]),
        Some(NEG_EPSILON)
    );
}

#[test]
fn ratio_cmp_refuses_zero_denominators() {
    assert_eq!(ratio_cmp(1, 0, 1, 1), None);
    assert_eq!(ratio_cmp(1, 1, 1, 0), None);
    assert_eq!(ratio_cmp(0, 0, 0, 0), None);
}

#[test]
fn ratio_cmp_is_exact_at_full_width() {
    assert_eq!(ratio_cmp(1, 2, 2, 4), Some(Ordering::Equal));
    assert_eq!(ratio_cmp(1, 3, 1, 2), Some(Ordering::Less));
    assert_eq!(ratio_cmp(u32::MAX, 1, u32::MAX, 1), Some(Ordering::Equal));
    assert_eq!(ratio_cmp(u32::MAX, u32::MAX, 1, 1), Some(Ordering::Equal));
    assert_eq!(
        ratio_cmp(u32::MAX, u32::MAX - 1, u32::MAX - 1, u32::MAX - 2),
        Some(Ordering::Less)
    );
    assert_eq!(ratio_cmp(0, u32::MAX, 0, 1), Some(Ordering::Equal));
    assert_eq!(
        ratio_cmp(u32::MAX, 1, u32::MAX - 1, 1),
        Some(Ordering::Greater)
    );
}

#[cfg(feature = "serde")]
#[test]
fn serde_round_trips_raw_bits() -> Result<(), serde_json::Error> {
    for value in [
        Q16_16::MIN,
        NEG_EPSILON,
        Q16_16::ZERO,
        HALF,
        Q16_16::ONE,
        Q16_16::MAX,
    ] {
        let encoded = serde_json::to_string(&value)?;
        assert_eq!(encoded, value.to_bits().to_string());
        assert_eq!(serde_json::from_str::<Q16_16>(&encoded)?, value);
    }
    assert!(serde_json::from_str::<Q16_16>("2147483648").is_err());
    assert!(serde_json::from_str::<Q16_16>("1.5").is_err());
    Ok(())
}
