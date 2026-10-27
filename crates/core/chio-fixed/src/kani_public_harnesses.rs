#![allow(clippy::arithmetic_side_effects)]

use core::cmp::Ordering;

use crate::{ratio_cmp, Q16_16};

#[kani::proof]
fn verify_q16_checked_mul_matches_i128_reference() {
    let a: i32 = kani::any();
    let b: i32 = kani::any();
    let reference = (i128::from(a) * i128::from(b)).div_euclid(1 << 16);
    let expected = i32::try_from(reference).ok().map(Q16_16::from_bits);
    assert_eq!(
        Q16_16::from_bits(a).checked_mul(Q16_16::from_bits(b)),
        expected
    );
}

#[kani::proof]
fn verify_q16_checked_add_never_wraps() {
    let a: i32 = kani::any();
    let b: i32 = kani::any();
    let exact = i64::from(a) + i64::from(b);
    match Q16_16::from_bits(a).checked_add(Q16_16::from_bits(b)) {
        Some(sum) => assert_eq!(i64::from(sum.to_bits()), exact),
        None => assert!(exact > i64::from(i32::MAX) || exact < i64::from(i32::MIN)),
    }
}

#[kani::proof]
fn verify_ratio_cmp_total_order() {
    let a: u32 = kani::any();
    let b: u32 = kani::any();
    let c: u32 = kani::any();
    let d: u32 = kani::any();
    let forward = ratio_cmp(a, b, c, d);
    if b == 0 || d == 0 {
        assert_eq!(forward, None);
    } else {
        let exact = (u128::from(a) * u128::from(d)).cmp(&(u128::from(c) * u128::from(b)));
        assert_eq!(forward, Some(exact));
        assert_eq!(ratio_cmp(c, d, a, b), Some(exact.reverse()));
        assert_eq!(ratio_cmp(a, b, a, b), Some(Ordering::Equal));
    }
}
