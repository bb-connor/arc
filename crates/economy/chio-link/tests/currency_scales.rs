use chio_link::convert::{convert_supported_units, minor_units_for_currency};
use chio_link::{ExchangeRate, PriceOracleError};

const CHIO_REFUSAL: &str = "no default minor-unit scale is pinned for currency CHIO";

fn rate(base: &str, quote: &str) -> ExchangeRate {
    ExchangeRate {
        base: base.to_string(),
        quote: quote.to_string(),
        rate_numerator: 1,
        rate_denominator: 0,
        updated_at: 1_743_292_740,
        fetched_at: 1_743_292_785,
        source: "chainlink".to_string(),
        feed_reference: "0xfeed".to_string(),
        max_age_seconds: 600,
        conversion_margin_bps: 0,
        confidence_numerator: None,
        confidence_denominator: None,
    }
}

fn assert_chio_refused(result: Result<u64, PriceOracleError>, context: &str) {
    match result {
        Err(PriceOracleError::InvalidConfiguration(message)) => {
            assert_eq!(message, CHIO_REFUSAL, "{context}");
        }
        other => panic!("{context}: expected InvalidConfiguration naming CHIO, got {other:?}"),
    }
}

#[test]
fn pinned_currencies_resolve_to_their_minor_unit_scales() -> Result<(), PriceOracleError> {
    let pinned: [(&str, u64); 9] = [
        ("USD", 100),
        ("EUR", 100),
        ("GBP", 100),
        ("JPY", 1),
        ("USDC", 1_000_000),
        ("USDT", 1_000_000),
        ("BTC", 100_000_000),
        ("ETH", 1_000_000_000_000_000_000),
        ("LINK", 1_000_000_000_000_000_000),
    ];
    for (currency, scale) in pinned {
        assert_eq!(minor_units_for_currency(currency)?, scale, "{currency}");
    }
    Ok(())
}

#[test]
fn chio_has_no_minor_unit_scale_in_any_case_or_padding() {
    for candidate in ["CHIO", "chio", "Chio", " CHIO ", "\tchio\n"] {
        assert_chio_refused(
            minor_units_for_currency(candidate),
            &format!("lookup of {candidate:?}"),
        );
    }
}

#[test]
fn chio_leg_on_either_side_refuses_before_conversion_arithmetic() {
    assert_chio_refused(
        convert_supported_units(1_000, &rate("CHIO", "USD"), 0),
        "CHIO base leg",
    );
    assert_chio_refused(
        convert_supported_units(1_000, &rate("USD", "chio"), 0),
        "CHIO quote leg",
    );
}
