use arc_link::config::PriceOracleConfig;
use arc_link::ExchangeRate;

#[test]
fn exchange_rate_helpers_reflect_public_contract() {
    let rate = ExchangeRate {
        base: "eth".to_string(),
        quote: "usd".to_string(),
        rate_numerator: 3_000,
        rate_denominator: 1,
        updated_at: 100,
        fetched_at: 110,
        source: "chainlink:base".to_string(),
        feed_reference: "feed-1".to_string(),
        max_age_seconds: 60,
        conversion_margin_bps: 25,
        confidence_numerator: None,
        confidence_denominator: None,
    };

    assert_eq!(rate.pair(), "ETH/USD");
    assert_eq!(rate.age_seconds(120), 20);
    assert!(rate.ensure_fresh(120).is_ok());
}

#[test]
fn default_price_oracle_config_validates() {
    let config = PriceOracleConfig::base_mainnet_default("http://localhost:8545");

    assert!(config.validate().is_ok());
}
