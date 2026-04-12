# Summary 135-02

Defined bounded decline and bind orchestration semantics over the pricing and
capital substrate.

## Delivered

- enforced action-specific quote, bind, and settlement reference requirements
  in `crates/arc-core/src/autonomy.rs`
- tied bind execution to explicit settlement-dispatch evidence over the
  official web3 lane

## Result

Automatic bind behavior is now explicit, interruptible, and subordinate to the
official execution rail.
