# chio-underwriting

`chio-underwriting` evaluates policy-input snapshots, builds decision artifacts,
prices premiums, and computes reputation-tiered marketplace credit limits.
It supplies the economy's decision and appeal vocabulary while applications
assemble evidence, sign artifacts, and persist decision lifecycle state.

## Usage

Quote a premium using caller-supplied compliance history:

```rust
use chio_underwriting::{price_premium, LookbackWindow, PremiumInputs};

fn main() -> Result<(), String> {
    let window = LookbackWindow::new(1_000, 2_000)?;
    let inputs = PremiumInputs::new(Some(950), None, 1_000, "USD");
    let quote = price_premium("agent-a", "tool:exec", window, &inputs);
    assert_eq!(quote.quoted_cents(), Some(2_000));
    assert_eq!(quote.combined_score(), Some(950));

    let unavailable = PremiumInputs::new(None, None, 1_000, "USD");
    assert!(price_premium("agent-a", "tool:exec", window, &unavailable).is_declined());
    Ok(())
}
```

The score is an input to this example. Applications must collect and
authenticate the evidence that supports it before relying on a quote.

## Guarantees

`price_premium` declines missing scores, invalid inputs, scores below its
configured floor, base rates beyond the exact range of a double, and overflowing monetary results.
It applies a capped behavioral penalty and checked integer pricing.
`LookbackWindow::new` rejects inverted ranges.

`evaluate_underwriting_policy_input` validates policy, folds evidence
findings into an outcome, and records reasons and remediation.
`build_underwriting_decision_artifact` hashes canonical decision content into a
stable ID and computes budget/premium recommendations. These entry points
consume plain snapshots; callers verify signed evidence before evaluation.
`compute_marketplace_credit_limit` denies a supplied revocation signal and
currencies outside its USD table.

## Status

Decision, premium, fiscal-policy adapter, simulation-report, and appeal types
are implemented. This crate performs no store reads, HTTP calls, budget
mutation, appeal resolution, or settlement dispatch. The control plane owns
those actions. `SignedUnderwritingDecision` uses the shared signed export
envelope, whose signature must be checked at the receiving boundary.
No Cargo features are declared.

## Related

- [Architecture](ARCHITECTURE.md)
- [Protocol trust-control contract](../../../spec/PROTOCOL.md#9-trust-control-contract)
- [Appraisal](../chio-appraisal/README.md)
- [Credit](../chio-credit/README.md)
- [License](../../../LICENSE)
