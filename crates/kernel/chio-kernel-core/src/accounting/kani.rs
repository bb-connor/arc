use super::*;
use crate::formal_aeneas::{ledger_apply, ReservationLedger};

#[kani::proof]
fn checked_exposure_matches_full_width_arithmetic() {
    let left: u64 = kani::any();
    let right: u64 = kani::any();
    let sum = u128::from(left) + u128::from(right);
    let result = ExposureUnits::new(left).try_add(ExposureUnits::new(right));
    match result {
        Ok(value) => assert_eq!(u128::from(value.get()), sum),
        Err(error) => {
            assert_eq!(error, AccountingError::ExposureOverflow);
            assert!(sum > u128::from(u64::MAX));
        }
    }
    match ExposureUnits::new(left).try_sub(ExposureUnits::new(right)) {
        Ok(value) => assert_eq!(
            u128::from(value.get()) + u128::from(right),
            u128::from(left)
        ),
        Err(error) => {
            assert_eq!(error, AccountingError::ExposureUnderflow);
            assert!(right > left);
        }
    }
}

#[kani::proof]
fn checked_balance_refines_reservation_conservation() {
    let exposed: u64 = kani::any();
    let spent: u64 = kani::any();
    let amount: u64 = kani::any();
    let realized: u64 = kani::any();
    let Ok(balance) = ExposureBalance::new(exposed, spent) else {
        return;
    };
    let state = ReservationLedger {
        reserved: exposed,
        committed: spent,
        released: 0,
        retained: 0,
    };
    let next = balance.settle(ExposureUnits::new(amount), ExposureUnits::new(realized));
    if amount > exposed || realized > amount {
        assert_eq!(next, Err(AccountingError::ExposureUnderflow));
        return;
    }
    // Independent scalar model: realize part of the reservation, then release
    // its remainder. The guard above proves this oracle subtraction.
    let released = amount - realized;
    let (projected, committed) = ledger_apply(state, 1, realized);
    let (projected, released_ok) = ledger_apply(projected, 2, released);
    assert!(committed && released_ok);
    match next {
        Ok(next) => {
            assert_eq!(next.exposed(), projected.reserved);
            assert_eq!(next.spent(), projected.committed);
            assert_eq!(
                u128::from(exposed) + u128::from(spent),
                u128::from(next.exposed())
                    + u128::from(next.spent())
                    + u128::from(projected.released)
            );
        }
        Err(_) => panic!("valid reservation settlement was refused"),
    }
}

#[kani::proof]
fn checked_invocations_preserve_the_count_domain() {
    let count: u32 = kani::any();
    let delta: u32 = kani::any();
    match InvocationCount::new(count).try_add(InvocationCount::new(delta)) {
        Ok(next) => assert_eq!(u64::from(next.get()), u64::from(count) + u64::from(delta)),
        Err(error) => {
            assert_eq!(error, AccountingError::InvocationOverflow);
            assert!(u64::from(count) + u64::from(delta) > u64::from(u32::MAX));
        }
    }
    match InvocationCount::new(count).try_sub(InvocationCount::new(delta)) {
        Ok(next) => assert_eq!(u64::from(next.get()) + u64::from(delta), u64::from(count)),
        Err(error) => {
            assert_eq!(error, AccountingError::InvocationUnderflow);
            assert!(delta > count);
        }
    }
}
