#![allow(clippy::expect_used, clippy::unwrap_used)]

use chio_core::{
    crypto::Keypair,
    receipt::{
        body::{ChioReceipt, ChioReceiptBody},
        decision::ToolCallAction,
        economics::{
            FinancialBudgetAuthorityReceiptMetadata, FinancialBudgetAuthorizeReceiptMetadata,
            FinancialBudgetHoldAuthorityMetadata, FinancialBudgetTerminalReceiptMetadata,
            FinancialReceiptMetadata, SettlementStatus,
        },
    },
};
use chio_kernel::budget_store::{
    BudgetAuthorizeHoldDecision, BudgetAuthorizeHoldRequest, BudgetReleaseHoldRequest,
    BudgetReverseHoldRequest,
};
use chio_kernel::{BudgetStore, BudgetStoreError, InMemoryBudgetStore};
use proptest::prelude::*;
use proptest::test_runner::Config as ProptestConfig;

const CAPABILITY_ID: &str = "cap-property";
const GRANT_INDEX: usize = 0;
const MAX_INVOCATIONS: Option<u32> = Some(8);
const MAX_COST_PER_INVOCATION: Option<u64> = Some(32);
const MAX_TOTAL_COST: Option<u64> = Some(128);

#[derive(Debug, Clone)]
enum BudgetOp {
    Authorize(u16),
    Release(u8, u16),
    Reverse(u8),
}

#[derive(Debug, Clone)]
struct HoldModel {
    remaining: u64,
    exposed: bool,
    reversed: bool,
}

#[derive(Debug, Clone, Default)]
struct BudgetModel {
    present: bool,
    invocation_count: u32,
    committed_cost_units: u64,
    holds: Vec<HoldModel>,
    seq: u64,
    next_seq: u64,
}

fn hold_id(index: usize) -> String {
    format!("hold-{index}")
}

impl BudgetModel {
    fn allocate_event_seq(&mut self) -> u64 {
        let event_seq = self.next_seq.saturating_add(1);
        self.next_seq = event_seq;
        event_seq
    }

    fn authorize(&mut self, cost_units: u64) -> Result<bool, &'static str> {
        let new_total = self
            .committed_cost_units
            .checked_add(cost_units)
            .ok_or("overflow")?;
        let allowed = MAX_INVOCATIONS.is_none_or(|max| self.invocation_count < max)
            && MAX_COST_PER_INVOCATION.is_none_or(|max| cost_units <= max)
            && MAX_TOTAL_COST.is_none_or(|max| new_total <= max);
        let event_seq = self.allocate_event_seq();
        if !allowed {
            return Ok(false);
        }
        self.invocation_count = self.invocation_count.saturating_add(1);
        self.committed_cost_units = new_total;
        self.holds.push(HoldModel {
            remaining: cost_units,
            exposed: cost_units > 0,
            reversed: false,
        });
        self.present = true;
        self.seq = event_seq;
        Ok(true)
    }

    fn release(&mut self, index: usize, cost_units: u64) -> Result<(), &'static str> {
        if cost_units == 0 {
            return Err("invariant");
        }
        let hold = self.holds.get_mut(index).ok_or("invariant")?;
        if hold.reversed || !hold.exposed || hold.remaining < cost_units {
            return Err("invariant");
        }
        hold.remaining -= cost_units;
        if hold.remaining == 0 {
            hold.exposed = false;
        }
        self.committed_cost_units -= cost_units;
        self.seq = self.allocate_event_seq();
        Ok(())
    }

    fn reverse(&mut self, index: usize) -> Result<(), &'static str> {
        let hold = self.holds.get_mut(index).ok_or("invariant")?;
        if hold.reversed {
            return Err("invariant");
        }
        let remaining = hold.remaining;
        hold.reversed = true;
        hold.remaining = 0;
        hold.exposed = false;
        self.invocation_count -= 1;
        self.committed_cost_units -= remaining;
        self.seq = self.allocate_event_seq();
        Ok(())
    }
}

fn budget_op_strategy() -> impl Strategy<Value = BudgetOp> {
    prop_oneof![
        (0u16..64).prop_map(BudgetOp::Authorize),
        (any::<u8>(), 0u16..64).prop_map(|(hold, units)| BudgetOp::Release(hold, units)),
        any::<u8>().prop_map(BudgetOp::Reverse),
    ]
}

fn pick_hold(model: &BudgetModel, pick: u8) -> usize {
    usize::from(pick) % (model.holds.len() + 1)
}

fn authorize_request(index: usize, cost_units: u64, max_total: Option<u64>) -> BudgetAuthorizeHoldRequest {
    BudgetAuthorizeHoldRequest {
        capability_id: CAPABILITY_ID.to_string(),
        grant_index: GRANT_INDEX,
        max_invocations: MAX_INVOCATIONS,
        invocation_quotas: Vec::new(),
        cumulative_approval: None,
        admission_binding: None,
        requested_exposure_units: cost_units,
        max_cost_per_invocation: MAX_COST_PER_INVOCATION,
        max_total_cost_units: max_total,
        hold_id: hold_id(index),
        event_id: format!("{}:authorize", hold_id(index)),
        authority: None,
    }
}

fn authorized(decision: Result<BudgetAuthorizeHoldDecision, BudgetStoreError>) -> Result<bool, BudgetStoreError> {
    decision.map(|decision| matches!(decision, BudgetAuthorizeHoldDecision::Authorized(_)))
}

fn error_kind(error: &BudgetStoreError) -> &'static str {
    match error {
        BudgetStoreError::Overflow(_) => "overflow",
        BudgetStoreError::Clock(_) => "clock",
        BudgetStoreError::Fenced { .. } => "fenced",
        BudgetStoreError::Invariant(_) => "invariant",
        BudgetStoreError::Sqlite(_) => "sqlite",
        BudgetStoreError::Io(_) => "io",
        BudgetStoreError::OutcomeUnknown(_) => "outcome_unknown",
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

fn assert_unit_result_matches<T: std::fmt::Debug>(
    actual: Result<T, BudgetStoreError>,
    expected: Result<(), &'static str>,
) {
    match (actual, expected) {
        (Ok(_), Ok(())) => {}
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
    assert_eq!(
        usage.committed_cost_units().unwrap(),
        model.committed_cost_units
    );
    assert_eq!(usage.seq, model.seq);
}

#[test]
fn financial_receipt_carries_hold_lineage_and_guarantee_level() {
    let keypair = Keypair::generate();
    let financial = FinancialReceiptMetadata {
        grant_index: 0,
        cost_charged: 75,
        currency: "USD".to_string(),
        budget_remaining: Some(925),
        budget_total: Some(1_000),
        delegation_depth: 1,
        root_budget_holder: "agent-root-001".to_string(),
        payment_reference: None,
        settlement_status: SettlementStatus::Settled,
        cost_breakdown: None,
        oracle_evidence: None,
        attempted_cost: None,
    };
    let budget_authority = FinancialBudgetAuthorityReceiptMetadata {
        guarantee_level: "ha_quorum_commit".to_string(),
        authority_profile: "authoritative_hold_event".to_string(),
        metering_profile: "max_cost_preauthorize_then_reconcile_actual".to_string(),
        hold_id: "budget-hold:req-1:cap-property:0".to_string(),
        budget_term: Some("http://leader-a:7".to_string()),
        authority: Some(FinancialBudgetHoldAuthorityMetadata {
            authority_id: "http://leader-a".to_string(),
            lease_id: "http://leader-a#term-7".to_string(),
            lease_epoch: 7,
        }),
        authorize: FinancialBudgetAuthorizeReceiptMetadata {
            event_id: Some("budget-hold:req-1:cap-property:0:authorize".to_string()),
            budget_commit_index: Some(41),
            exposure_units: 120,
            committed_cost_units_after: 120,
        },
        terminal: Some(FinancialBudgetTerminalReceiptMetadata {
            disposition: "reconciled".to_string(),
            event_id: Some("budget-hold:req-1:cap-property:0:reconcile".to_string()),
            budget_commit_index: Some(42),
            exposure_units: 120,
            realized_spend_units: 75,
            committed_cost_units_after: 75,
        }),
    };
    let receipt = ChioReceipt::sign(
        ChioReceiptBody {
            id: "rcpt-budget-lineage-1".to_string(),
            timestamp: 1_710_000_000,
            capability_id: CAPABILITY_ID.to_string(),
            tool_server: "shell".to_string(),
            tool_name: "bash".to_string(),
            action: ToolCallAction::from_parameters(serde_json::json!({"command": "true"}))
                .expect("build action"),
            decision: Some(chio_core::receipt::decision::Decision::Allow),
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: Default::default(),
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            content_hash: "content-hash-1".to_string(),
            policy_hash: "policy-hash-1".to_string(),
            evidence: Vec::new(),
            metadata: Some(serde_json::json!({
                "financial": financial.clone(),
                "budget_authority": budget_authority.clone(),
            })),
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
            tenant_id: None,
            kernel_key: keypair.public_key(),
            bbs_projection_version: None,
        },
        &keypair,
    )
    .expect("sign receipt");

    let extracted_financial = receipt
        .financial_metadata()
        .expect("extract financial metadata");
    assert_eq!(extracted_financial.grant_index, financial.grant_index);
    assert_eq!(extracted_financial.cost_charged, financial.cost_charged);
    assert_eq!(extracted_financial.currency, financial.currency);
    assert_eq!(
        extracted_financial.budget_remaining,
        financial.budget_remaining
    );
    assert_eq!(extracted_financial.budget_total, financial.budget_total);
    assert_eq!(
        extracted_financial.root_budget_holder,
        financial.root_budget_holder
    );
    let extracted = receipt
        .financial_budget_authority_metadata()
        .expect("extract budget authority");
    assert_eq!(extracted.guarantee_level, "ha_quorum_commit");
    assert_eq!(extracted.hold_id, "budget-hold:req-1:cap-property:0");
    assert_eq!(extracted.budget_term.as_deref(), Some("http://leader-a:7"));
    assert_eq!(
        extracted
            .authority
            .as_ref()
            .map(|authority| authority.authority_id.as_str()),
        Some("http://leader-a")
    );
    assert_eq!(
        extracted.authorize.event_id.as_deref(),
        Some("budget-hold:req-1:cap-property:0:authorize")
    );
    assert_eq!(
        extracted
            .terminal
            .as_ref()
            .and_then(|terminal| terminal.event_id.as_deref()),
        Some("budget-hold:req-1:cap-property:0:reconcile")
    );
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
        let store = InMemoryBudgetStore::new();
        let mut model = BudgetModel::default();

        let mut attempts = 0usize;
        for (step, operation) in operations.into_iter().enumerate() {
            match operation {
                BudgetOp::Authorize(cost_units) => {
                    let index = attempts;
                    attempts += 1;
                    let actual = authorized(store.authorize_budget_hold(authorize_request(
                        index,
                        u64::from(cost_units),
                        MAX_TOTAL_COST,
                    )));
                    let expected = model.authorize(u64::from(cost_units));
                    if expected != Ok(true) {
                        model.holds.push(HoldModel {
                            remaining: 0,
                            exposed: false,
                            reversed: true,
                        });
                    }
                    assert_charge_result_matches(actual, expected);
                }
                BudgetOp::Release(pick, cost_units) => {
                    let index = pick_hold(&model, pick);
                    let actual = store.release_budget_hold(BudgetReleaseHoldRequest {
                        capability_id: CAPABILITY_ID.to_string(),
                        grant_index: GRANT_INDEX,
                        released_exposure_units: u64::from(cost_units),
                        hold_id: hold_id(index),
                        event_id: format!("{}:release:{step}", hold_id(index)),
                        authority: None,
                    });
                    let expected = model.release(index, u64::from(cost_units));
                    assert_unit_result_matches(actual, expected);
                }
                BudgetOp::Reverse(pick) => {
                    let index = pick_hold(&model, pick);
                    let remaining = model.holds.get(index).map_or(0, |hold| hold.remaining);
                    let actual = store.reverse_budget_hold(BudgetReverseHoldRequest {
                        capability_id: CAPABILITY_ID.to_string(),
                        grant_index: GRANT_INDEX,
                        reversed_exposure_units: remaining,
                        hold_id: hold_id(index),
                        event_id: format!("{}:reverse:{step}", hold_id(index)),
                        expected_cumulative_approval_state: None,
                        authority: None,
                    });
                    let expected = model.reverse(index);
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
        let store = InMemoryBudgetStore::new();
        let first_charge = u64::MAX - u64::from(slack);
        let second_charge = u64::from(slack) + u64::from(overflow_by);

        let mut first = authorize_request(0, first_charge, Some(u64::MAX));
        first.max_cost_per_invocation = None;
        let accepted = authorized(store.authorize_budget_hold(first)).unwrap();
        prop_assert!(accepted);

        let mut second = authorize_request(1, second_charge, Some(u64::MAX));
        second.max_cost_per_invocation = None;
        let overflow = store.authorize_budget_hold(second);
        prop_assert!(matches!(overflow, Err(BudgetStoreError::Overflow(_))));

        let usage = store.get_usage(CAPABILITY_ID, GRANT_INDEX).unwrap().unwrap();
        prop_assert_eq!(usage.invocation_count, 1);
        prop_assert_eq!(usage.committed_cost_units().unwrap(), first_charge);
        prop_assert_eq!(usage.seq, 1);
    }
}
