#![allow(clippy::expect_used, clippy::unwrap_used)]

use arc_kernel::{BudgetStore, BudgetStoreError, InMemoryBudgetStore};
use proptest::prelude::*;
use proptest::test_runner::Config as ProptestConfig;

const CAPABILITY_ID: &str = "cap-property";
const GRANT_INDEX: usize = 0;
const MAX_INVOCATIONS: Option<u32> = Some(8);
const MAX_COST_PER_INVOCATION: Option<u64> = Some(32);
const MAX_TOTAL_COST: Option<u64> = Some(128);

#[derive(Debug, Clone)]
enum BudgetOp {
    Charge(u16),
    Reduce(u16),
    Reverse(u16),
}

#[derive(Debug, Clone, Default)]
struct BudgetModel {
    present: bool,
    invocation_count: u32,
    total_cost_charged: u64,
    seq: u64,
}

impl BudgetModel {
    fn try_charge_cost(
        &mut self,
        cost_units: u64,
        max_invocations: Option<u32>,
        max_cost_per_invocation: Option<u64>,
        max_total_cost: Option<u64>,
    ) -> Result<bool, &'static str> {
        self.present = true;

        if let Some(max) = max_invocations {
            if self.invocation_count >= max {
                return Ok(false);
            }
        }

        if let Some(max) = max_cost_per_invocation {
            if cost_units > max {
                return Ok(false);
            }
        }

        let new_total = if let Some(max_total) = max_total_cost {
            let total = self
                .total_cost_charged
                .checked_add(cost_units)
                .ok_or("overflow")?;
            if total > max_total {
                return Ok(false);
            }
            total
        } else {
            self.total_cost_charged.saturating_add(cost_units)
        };

        self.invocation_count = self.invocation_count.saturating_add(1);
        self.total_cost_charged = new_total;
        self.seq = self.seq.saturating_add(1);
        Ok(true)
    }

    fn reverse_charge_cost(&mut self, cost_units: u64) -> Result<(), &'static str> {
        if !self.present {
            return Err("invariant");
        }
        if self.invocation_count == 0 {
            return Err("invariant");
        }
        if self.total_cost_charged < cost_units {
            return Err("invariant");
        }

        self.invocation_count -= 1;
        self.total_cost_charged -= cost_units;
        self.seq = self.seq.saturating_add(1);
        Ok(())
    }

    fn reduce_charge_cost(&mut self, cost_units: u64) -> Result<(), &'static str> {
        if !self.present {
            return Err("invariant");
        }
        if self.total_cost_charged < cost_units {
            return Err("invariant");
        }

        self.total_cost_charged -= cost_units;
        self.seq = self.seq.saturating_add(1);
        Ok(())
    }
}

fn budget_op_strategy() -> impl Strategy<Value = BudgetOp> {
    prop_oneof![
        (0u16..64).prop_map(BudgetOp::Charge),
        (0u16..64).prop_map(BudgetOp::Reduce),
        (0u16..64).prop_map(BudgetOp::Reverse),
    ]
}

fn error_kind(error: &BudgetStoreError) -> &'static str {
    match error {
        BudgetStoreError::Overflow(_) => "overflow",
        BudgetStoreError::Invariant(_) => "invariant",
        BudgetStoreError::Sqlite(_) => "sqlite",
        BudgetStoreError::Io(_) => "io",
    }
}

fn assert_charge_result_matches(
    actual: Result<bool, BudgetStoreError>,
    expected: Result<bool, &'static str>,
) {
    match (actual, expected) {
        (Ok(actual), Ok(expected)) => assert_eq!(actual, expected),
        (Err(actual), Err(expected)) => assert_eq!(error_kind(&actual), expected),
        (actual, expected) => {
            panic!("charge result mismatch: actual={actual:?}, expected={expected:?}")
        }
    }
}

fn assert_unit_result_matches(
    actual: Result<(), BudgetStoreError>,
    expected: Result<(), &'static str>,
) {
    match (actual, expected) {
        (Ok(actual), Ok(expected)) => assert_eq!(actual, expected),
        (Err(actual), Err(expected)) => assert_eq!(error_kind(&actual), expected),
        (actual, expected) => {
            panic!("mutation result mismatch: actual={actual:?}, expected={expected:?}")
        }
    }
}

fn assert_store_matches_model(store: &InMemoryBudgetStore, model: &BudgetModel) {
    let usage = store.get_usage(CAPABILITY_ID, GRANT_INDEX).unwrap();
    if !model.present {
        assert!(usage.is_none());
        return;
    }

    let usage = usage.expect("budget row should exist");
    assert_eq!(usage.capability_id, CAPABILITY_ID);
    assert_eq!(usage.grant_index, GRANT_INDEX as u32);
    assert_eq!(usage.invocation_count, model.invocation_count);
    assert_eq!(usage.total_cost_charged, model.total_cost_charged);
    assert_eq!(usage.seq, model.seq);
}

proptest! {
    #![proptest_config(ProptestConfig {
        failure_persistence: None,
        .. ProptestConfig::default()
    })]

    #[test]
    fn budget_store_matches_reference_model_under_random_operation_sequences(
        operations in proptest::collection::vec(budget_op_strategy(), 1..64),
    ) {
        let mut store = InMemoryBudgetStore::new();
        let mut model = BudgetModel::default();

        for operation in operations {
            match operation {
                BudgetOp::Charge(cost_units) => {
                    let actual = store.try_charge_cost(
                        CAPABILITY_ID,
                        GRANT_INDEX,
                        MAX_INVOCATIONS,
                        u64::from(cost_units),
                        MAX_COST_PER_INVOCATION,
                        MAX_TOTAL_COST,
                    );
                    let expected = model.try_charge_cost(
                        u64::from(cost_units),
                        MAX_INVOCATIONS,
                        MAX_COST_PER_INVOCATION,
                        MAX_TOTAL_COST,
                    );
                    assert_charge_result_matches(actual, expected);
                }
                BudgetOp::Reduce(cost_units) => {
                    let actual = store.reduce_charge_cost(
                        CAPABILITY_ID,
                        GRANT_INDEX,
                        u64::from(cost_units),
                    );
                    let expected = model.reduce_charge_cost(u64::from(cost_units));
                    assert_unit_result_matches(actual, expected);
                }
                BudgetOp::Reverse(cost_units) => {
                    let actual = store.reverse_charge_cost(
                        CAPABILITY_ID,
                        GRANT_INDEX,
                        u64::from(cost_units),
                    );
                    let expected = model.reverse_charge_cost(u64::from(cost_units));
                    assert_unit_result_matches(actual, expected);
                }
            }

            assert_store_matches_model(&store, &model);
        }
    }

    #[test]
    fn total_cost_overflow_is_reported_before_state_wraps(
        slack in 0u16..=1024,
        overflow_by in 1u16..=1024,
    ) {
        let mut store = InMemoryBudgetStore::new();
        let first_charge = u64::MAX - u64::from(slack);
        let second_charge = u64::from(slack) + u64::from(overflow_by);

        let accepted = store.try_charge_cost(
            CAPABILITY_ID,
            GRANT_INDEX,
            Some(4),
            first_charge,
            None,
            Some(u64::MAX),
        ).unwrap();
        prop_assert!(accepted);

        let overflow = store.try_charge_cost(
            CAPABILITY_ID,
            GRANT_INDEX,
            Some(4),
            second_charge,
            None,
            Some(u64::MAX),
        );
        prop_assert!(matches!(overflow, Err(BudgetStoreError::Overflow(_))));

        let usage = store.get_usage(CAPABILITY_ID, GRANT_INDEX).unwrap().unwrap();
        prop_assert_eq!(usage.invocation_count, 1);
        prop_assert_eq!(usage.total_cost_charged, first_charge);
        prop_assert_eq!(usage.seq, 1);
    }
}
