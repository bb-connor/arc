#![allow(clippy::unwrap_used, clippy::expect_used)]

use chio_settle::PreparedSolanaSettlement;

const EXAMPLE: &str =
    include_str!("../../../../docs/standards/CHIO_SETTLE_SOLANA_RELEASE_EXAMPLE.json");

#[test]
fn committed_placeholder_solana_release_example_is_refused() {
    let error = serde_json::from_str::<PreparedSolanaSettlement>(EXAMPLE).unwrap_err();
    assert_eq!(error.classify(), serde_json::error::Category::Data);
    assert!(error.to_string().starts_with("unknown field `schema`"));
}
