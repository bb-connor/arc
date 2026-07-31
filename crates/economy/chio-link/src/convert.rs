use crate::{ExchangeRate, PriceOracleError};

const BPS_DENOMINATOR: u128 = 10_000;

pub fn minor_units_for_currency(currency: &str) -> Result<u64, PriceOracleError> {
    match currency.trim().to_ascii_uppercase().as_str() {
        "USD" | "EUR" | "GBP" => Ok(100),
        // XCC (the Chio Pass free-tier allotment unit) is deliberately ABSENT.
        // The Pass free-tier pool detector in chio-kernel classifies a unit as
        // private-use only when `minor_units_for_currency(currency).is_err()`, so
        // pinning a minor-unit scale here would re-route genuine XCC grants onto
        // the normal budget path and let Passes bypass the aggregate
        // `freetier:global` pool ceiling. XCC must stay unpriced (no money leg);
        // the off-chain credit netting carries its own canonical rate table and
        // never consults this function for XCC.
        "JPY" => Ok(1),
        "USDC" | "USDT" => Ok(1_000_000),
        "BTC" => Ok(100_000_000),
        "ETH" | "LINK" => Ok(1_000_000_000_000_000_000),
        other => Err(PriceOracleError::InvalidConfiguration(format!(
            "no default minor-unit scale is pinned for currency {other}"
        ))),
    }
}

pub fn convert_supported_units(
    original_units: u64,
    rate: &ExchangeRate,
    margin_bps: u32,
) -> Result<u64, PriceOracleError> {
    convert_units(
        original_units,
        minor_units_for_currency(&rate.base)?,
        minor_units_for_currency(&rate.quote)?,
        rate,
        margin_bps,
    )
}

pub fn convert_units(
    original_units: u64,
    base_minor_units_per_unit: u64,
    quote_minor_units_per_unit: u64,
    rate: &ExchangeRate,
    margin_bps: u32,
) -> Result<u64, PriceOracleError> {
    if base_minor_units_per_unit == 0 || quote_minor_units_per_unit == 0 {
        return Err(PriceOracleError::InvalidConfiguration(
            "currency scales must be non-zero".to_string(),
        ));
    }
    if rate.rate_denominator == 0 {
        return Err(PriceOracleError::InvalidFeed(format!(
            "{} returned a zero rate denominator",
            rate.pair()
        )));
    }
    let numerator = u128::from(original_units)
        .checked_mul(rate.rate_numerator)
        .and_then(|value| value.checked_mul(u128::from(quote_minor_units_per_unit)))
        .ok_or_else(|| {
            PriceOracleError::ArithmeticOverflow(format!(
                "conversion numerator overflowed for {}",
                rate.pair()
            ))
        })?;
    let denominator = u128::from(base_minor_units_per_unit)
        .checked_mul(rate.rate_denominator)
        .ok_or_else(|| {
            PriceOracleError::ArithmeticOverflow(format!(
                "conversion denominator overflowed for {}",
                rate.pair()
            ))
        })?;
    let converted = numerator.div_ceil(denominator);
    let with_margin = if margin_bps == 0 {
        converted
    } else {
        converted
            .checked_mul(BPS_DENOMINATOR + u128::from(margin_bps))
            .ok_or_else(|| {
                PriceOracleError::ArithmeticOverflow(format!(
                    "margin application overflowed for {}",
                    rate.pair()
                ))
            })?
            .div_ceil(BPS_DENOMINATOR)
    };
    u64::try_from(with_margin).map_err(|_| {
        PriceOracleError::ArithmeticOverflow(format!(
            "converted units exceeded u64 for {}",
            rate.pair()
        ))
    })
}

#[cfg(test)]
mod tests {
    use crate::test_support::TestUnwrap;
    use crate::ExchangeRate;

    use super::{convert_supported_units, convert_units, minor_units_for_currency};

    fn sample_rate() -> ExchangeRate {
        ExchangeRate {
            base: "ETH".to_string(),
            quote: "USD".to_string(),
            rate_numerator: 300_000,
            rate_denominator: 100,
            updated_at: 1_743_292_740,
            fetched_at: 1_743_292_785,
            source: "chainlink".to_string(),
            feed_reference: "0x71041dddad3595F9CEd3DcCFBe3D1F4b0a16Bb70".to_string(),
            max_age_seconds: 600,
            conversion_margin_bps: 200,
            confidence_numerator: None,
            confidence_denominator: None,
        }
    }

    #[test]
    fn converts_with_ceiling_rounding() {
        let converted = convert_units(
            1_000_000_000_000_000,
            1_000_000_000_000_000_000,
            100,
            &sample_rate(),
            0,
        )
        .test_unwrap("converted");
        assert_eq!(converted, 300);
    }

    #[test]
    fn applies_margin_conservatively() {
        let converted = convert_units(
            1_000_000_000_000_000,
            1_000_000_000_000_000_000,
            100,
            &sample_rate(),
            200,
        )
        .test_unwrap("converted");
        assert_eq!(converted, 306);
    }

    #[test]
    fn resolves_supported_currency_scales() {
        assert_eq!(minor_units_for_currency("USD").test_unwrap("usd"), 100);
        assert_eq!(
            minor_units_for_currency("ETH").test_unwrap("eth"),
            10_u64.pow(18)
        );
    }

    #[test]
    fn converts_with_default_supported_scales() {
        let converted = convert_supported_units(1_000_000_000_000_000, &sample_rate(), 0)
            .test_unwrap("converted");
        assert_eq!(converted, 300);
    }

    #[test]
    fn xcc_stays_unpriced_for_the_pass_pool_gate() {
        // XCC (the Chio Pass free-tier allotment unit) MUST stay
        // unpriced. The kernel free-tier pool detector classifies a unit as
        // private-use only when this lookup fails, so pinning XCC here would
        // re-route genuine XCC grants onto the normal budget path and bypass the
        // aggregate pool ceiling. Every spelling must fail closed.
        for candidate in ["XCC", "xcc", " xcc ", " XCC "] {
            assert!(
                matches!(
                    minor_units_for_currency(candidate),
                    Err(crate::PriceOracleError::InvalidConfiguration(_))
                ),
                "XCC must stay unpriced so the Pass pool gate routes it, got a price for {candidate:?}"
            );
        }
    }

    #[test]
    fn rejects_non_three_letter_credit_code() {
        // A non-3-letter code such as "CHIOCREDIT" is not pinned and must
        // fail closed through the catch-all guard rather than resolve.
        assert!(matches!(
            minor_units_for_currency("CHIOCREDIT"),
            Err(crate::PriceOracleError::InvalidConfiguration(_))
        ));
    }
}

#[cfg(test)]
mod do_not_weaken {
    //! DO-NOT-WEAKEN regression suite.
    //!
    //! The pinned minor-unit table in `minor_units_for_currency` lists
    //! exactly USD, EUR, GBP, JPY, USDC, USDT, BTC, ETH, and LINK. CHIO
    //! is deliberately ABSENT: the protocol pins no native minor-unit
    //! scale for a Chio token, so any attempt to resolve or convert a
    //! "CHIO" amount must fail closed rather than invent a scale. Adding
    //! a CHIO arm here would weaken budget conversion; do not do it.
    use crate::test_support::TestUnwrap;
    use crate::{ExchangeRate, PriceOracleError};

    use super::{convert_supported_units, minor_units_for_currency};

    const PINNED_CURRENCIES: [&str; 9] = [
        "USD", "EUR", "GBP", "JPY", "USDC", "USDT", "BTC", "ETH", "LINK",
    ];

    fn rate_for(base: &str, quote: &str) -> ExchangeRate {
        ExchangeRate {
            base: base.to_string(),
            quote: quote.to_string(),
            rate_numerator: 1,
            rate_denominator: 1,
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

    #[test]
    fn pinned_currencies_resolve_and_chio_is_not_pinned() {
        for currency in PINNED_CURRENCIES {
            let scale = minor_units_for_currency(currency).test_unwrap("pinned currency resolves");
            assert!(
                scale > 0,
                "pinned currency {currency} must resolve to a non-zero scale"
            );
        }
        assert!(
            !PINNED_CURRENCIES.contains(&"CHIO"),
            "CHIO must never be added to the pinned currency table"
        );
    }

    #[test]
    fn chio_lookup_fails_closed() {
        // Deliberate injection: every spelling of CHIO must fail closed.
        for candidate in ["CHIO", "chio", "Chio", " CHIO "] {
            match minor_units_for_currency(candidate) {
                Err(PriceOracleError::InvalidConfiguration(message)) => {
                    assert!(
                        message.contains("CHIO"),
                        "expected the CHIO rejection to name the currency, got {message:?}"
                    );
                }
                other => panic!("expected CHIO lookup to fail closed, got {other:?}"),
            }
        }
    }

    #[test]
    fn converting_a_chio_denominated_rate_fails_closed() {
        // Deliberate injection: a rate naming CHIO on either leg must be
        // rejected before any conversion arithmetic runs.
        let base_chio = convert_supported_units(1_000, &rate_for("CHIO", "USD"), 0);
        assert!(
            matches!(base_chio, Err(PriceOracleError::InvalidConfiguration(_))),
            "CHIO base leg must fail closed, got {base_chio:?}"
        );
        let quote_chio = convert_supported_units(1_000, &rate_for("USD", "CHIO"), 0);
        assert!(
            matches!(quote_chio, Err(PriceOracleError::InvalidConfiguration(_))),
            "CHIO quote leg must fail closed, got {quote_chio:?}"
        );
    }
}
