//! Malformed signed validity and monetary inputs must never reach dispatch.
use chio_composed_baseline::receiver::{BaselineProfile, ComposedReceiver, DurabilityMode};
use chio_composed_baseline::scenario::{self, CallBuilder, Keys};
use chio_composed_baseline::store::BaselineStore;
use serde_json::{json, Value};
use std::path::Path;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn hardened_receiver_rejects_future_or_reversed_issuance_windows() -> TestResult {
    for (iat, exp) in [
        (scenario::NOW_S + 86_401, scenario::NOW_S + 86_400),
        (scenario::NOW_S + 60, scenario::NOW_S + 120),
        (scenario::NOW_S + 86_400, scenario::NOW_S + 86_400),
    ] {
        rejected_call(BaselineProfile::Hardened, "token.window_invalid", |call| {
            call.claims.iat = iat;
            call.claims.exp = exp;
        })?;
    }
    Ok(())
}

#[test]
fn neither_receiver_treats_invalid_refund_amounts_as_zero() -> TestResult {
    for profile in [BaselineProfile::Composed, BaselineProfile::Hardened] {
        for amount in [
            None,
            Some(json!("1000000")),
            Some(json!(-1)),
            Some(json!(0.5)),
            Some(Value::Null),
        ] {
            rejected_call(profile, "policy.amount_invalid", |call| {
                if let Some(amount) = amount {
                    call.arguments["amount_minor"] = amount;
                } else if let Some(arguments) = call.arguments.as_object_mut() {
                    arguments.remove("amount_minor");
                }
            })?;
        }
    }
    Ok(())
}

fn rejected_call(
    profile: BaselineProfile,
    code: &str,
    change: impl FnOnce(&mut CallBuilder<'_>),
) -> TestResult {
    let keys = Keys::fixed();
    let state = scenario::vendor_state(&keys, false);
    let store = BaselineStore::open(Path::new(":memory:"))?;
    let receiver = ComposedReceiver {
        state: &state,
        profile,
        durability: DurabilityMode::BeforeDispatch,
        signing_key: &keys.vendor_decision,
        store: &store,
        private_profile: None,
    };
    let mut call = CallBuilder::new(&keys, "invalid-boundary");
    change(&mut call);
    let mut dispatched = false;
    let outcome = receiver.admit(&call.build()?, scenario::NOW_MS, &mut |_| dispatched = true)?;
    assert!(!dispatched && !outcome.dispatched && !outcome.admitted);
    assert_eq!(outcome.denial_code.as_deref(), Some(code));
    Ok(())
}
