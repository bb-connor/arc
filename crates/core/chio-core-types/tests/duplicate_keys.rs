//! Manifest optional members refuse a repeated object key on raw input.

use chio_core_types::capability::scope::MonetaryAmount;
use chio_core_types::manifest::{PricingModel, ToolAnnotations, ToolDefinition, ToolPricing};
use chio_test_support::duplicate_keys::assert_repeated_member_refused;
use chio_test_support::prelude::*;

#[test]
fn manifest_optional_members_refuse_a_repeated_key() {
    let pricing = ToolPricing {
        pricing_model: PricingModel::Flat,
        base_price: Some(MonetaryAmount {
            units: 5,
            currency: "USD".to_string(),
        }),
        unit_price: None,
        billing_unit: None,
    };
    let tool = ToolDefinition {
        name: "search".to_string(),
        description: "Search".to_string(),
        input_schema: serde_json::json!({"type": "object"}),
        output_schema: None,
        pricing: Some(pricing.clone()),
        annotations: ToolAnnotations::default(),
        latency_hint: None,
        flow: None,
    };
    let document = serde_json::to_string(&tool).test_unwrap();
    assert_repeated_member_refused::<ToolDefinition>(
        &document,
        &serde_json::to_string(&pricing).test_unwrap(),
    );
    assert_repeated_member_refused::<ToolDefinition>(
        &document,
        &serde_json::to_string(&pricing.base_price).test_unwrap(),
    );
}
