use super::*;
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn amounts_match_wide_integer_arithmetic(left: u64, right: u64) {
        let left_units = ExposureUnits::new(left);
        let right_units = ExposureUnits::new(right);
        let sum = u128::from(left) + u128::from(right);
        match left_units.try_add(right_units) {
            Ok(value) => prop_assert_eq!(u128::from(value.get()), sum),
            Err(error) => {
                prop_assert_eq!(error, AccountingError::ExposureOverflow);
                prop_assert!(sum > u128::from(u64::MAX));
            }
        }
        match left_units.try_sub(right_units) {
            Ok(value) => prop_assert_eq!(u128::from(value.get()) + u128::from(right), u128::from(left)),
            Err(error) => {
                prop_assert_eq!(error, AccountingError::ExposureUnderflow);
                prop_assert!(right > left);
            }
        }
    }

    #[test]
    fn settlement_conserves_committed_plus_released(exposed: u64, spent: u64, reservation: u64, realized: u64) {
        let Ok(balance) = ExposureBalance::new(exposed, spent) else {
            prop_assert!(u128::from(exposed) + u128::from(spent) > u128::from(u64::MAX));
            return Ok(());
        };
        let result = balance.settle(ExposureUnits::new(reservation), ExposureUnits::new(realized));
        if reservation <= exposed && realized <= reservation {
            let next = result.unwrap();
            prop_assert_eq!(u128::from(next.exposed()) + u128::from(reservation), u128::from(exposed));
            prop_assert_eq!(u128::from(next.spent()), u128::from(spent) + u128::from(realized));
            prop_assert_eq!(u128::from(next.committed().unwrap().get()) + u128::from(reservation),
                u128::from(balance.committed().unwrap().get()) + u128::from(realized));
        } else {
            prop_assert_eq!(result, Err(AccountingError::ExposureUnderflow));
        }
    }
}

#[test]
fn exact_domain_boundaries_return_specific_errors() {
    let maximum = ExposureUnits::new(u64::MAX);
    assert_eq!(maximum.try_add(ExposureUnits::ZERO), Ok(maximum));
    assert_eq!(maximum.try_sub(maximum), Ok(ExposureUnits::ZERO));
    assert_eq!(
        maximum.try_add(ExposureUnits::new(1)),
        Err(AccountingError::ExposureOverflow)
    );
    assert_eq!(
        ExposureUnits::ZERO.try_sub(ExposureUnits::new(1)),
        Err(AccountingError::ExposureUnderflow)
    );
    assert_eq!(
        InvocationCount::new(u32::MAX).try_add(InvocationCount::ONE),
        Err(AccountingError::InvocationOverflow)
    );
    assert_eq!(
        InvocationCount::new(0).try_sub(InvocationCount::ONE),
        Err(AccountingError::InvocationUnderflow)
    );
    assert_eq!(
        ExposureBalance::new(u64::MAX, 1),
        Err(AccountingError::ExposureOverflow)
    );
    let balance = ExposureBalance::new(u64::MAX, 0).unwrap();
    let settled = balance.settle(maximum, maximum).unwrap();
    assert_eq!((settled.exposed(), settled.spent()), (0, u64::MAX));
    assert_eq!(
        settled.charge(ExposureUnits::new(1)),
        Err(AccountingError::ExposureOverflow)
    );
}
