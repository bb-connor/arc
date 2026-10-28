use chio_underwriting::{
    price_premium, LookbackWindow, PremiumDeclineReason, PremiumInputs, PremiumQuote,
};

fn window() -> Result<LookbackWindow, String> {
    LookbackWindow::new(1_000_000, 1_000_600)
}

fn currency_refusal(currency: &str) -> String {
    format!("premium currency must be a three-letter uppercase ISO-style code, got `{currency}`")
}

#[test]
fn premium_validation_refuses_non_iso_currencies() {
    for currency in ["CHIOCREDIT", "CHIO", "USDC", "usd", "Usd", "chi"] {
        let inputs = PremiumInputs::new(Some(950), None, 1_000, currency);
        assert_eq!(
            inputs.validate(),
            Err(currency_refusal(currency)),
            "{currency}"
        );
    }
}

#[test]
fn premium_validation_accepts_three_uppercase_letters() {
    for currency in ["USD", "EUR", "JPY"] {
        let inputs = PremiumInputs::new(Some(950), None, 1_000, currency);
        assert_eq!(inputs.validate(), Ok(()), "{currency}");
    }
}

#[test]
fn chio_style_premium_currency_declines_as_invalid_inputs() -> Result<(), String> {
    let inputs = PremiumInputs::new(Some(950), None, 1_000, "CHIOCREDIT");
    let quote = price_premium("agent-chio", "tool:exec", window()?, &inputs);
    match quote {
        PremiumQuote::Declined {
            reason: PremiumDeclineReason::InvalidInputs,
            combined_score: None,
            justification,
            ..
        } => {
            assert_eq!(
                justification,
                format!(
                    "premium inputs failed validation: {}",
                    currency_refusal("CHIOCREDIT")
                )
            );
        }
        other => panic!("expected an InvalidInputs decline, got {other:?}"),
    }
    Ok(())
}
