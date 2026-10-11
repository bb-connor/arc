use super::*;

#[test]
fn budget_ceilings_require_explicit_null_or_full_width_amounts() {
    for ceiling in [None, Some(u64::MAX), Some(1_000)] {
        let wire = serde_json::json!({
            "grant_index": 0, "cost_charged": 75, "currency": "USD",
            "budget_total": ceiling, "budget_remaining": ceiling.map(|v| v - 75),
            "delegation_depth": 0, "root_budget_holder": "root",
            "settlement_status": "pending"
        });
        let financial: FinancialReceiptMetadata = serde_json::from_value(wire.clone()).unwrap();
        let economic: EconomicBudgetReceiptMetadata = serde_json::from_value(wire.clone()).unwrap();
        assert_eq!(financial.budget_total, ceiling);
        assert_eq!(economic.budget_total, ceiling);
        assert_eq!(financial.budget_remaining, ceiling.map(|v| v - 75));
        assert_eq!(economic.budget_remaining, financial.budget_remaining);
        assert_eq!(
            serde_json::to_value(financial).unwrap()["budget_total"],
            wire["budget_total"]
        );
        for field in ["budget_total", "budget_remaining"] {
            let mut missing = wire.clone();
            missing.as_object_mut().unwrap().remove(field);
            let financial = serde_json::from_value::<FinancialReceiptMetadata>(missing.clone())
                .expect_err("a missing field must not become uncapped authority");
            let economic = serde_json::from_value::<EconomicBudgetReceiptMetadata>(missing)
                .expect_err("a missing field must not become uncapped authority");
            assert!(financial.is_data());
            assert!(economic.is_data());
            assert_eq!(financial.to_string(), format!("missing field `{field}`"));
            assert_eq!(economic.to_string(), financial.to_string());
        }
    }
}
