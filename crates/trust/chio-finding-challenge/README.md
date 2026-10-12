# chio-finding-challenge

Pure adjudication of signed cognition-market finding challenges. The crate
consumes retained admission pins and resolved evidence, then returns a typed
result for the coordinator to sign and enforce.

## Usage

Call the evaluator after assembling `FindingChallengeEvaluationInput` from
independently authenticated admission, authority-status, and evidence records.
This wrapper shows the penalty decision; the assertions exercise the reason
mapping without constructing a complete signed market submission.

```rust
use chio_finding::FindingChallengeVerdict;
use chio_finding_challenge::{
    evaluate_finding_challenge, FindingChallengeEvaluationInput,
    FindingChallengeReason,
};

fn penalty_permitted(input: &FindingChallengeEvaluationInput<'_>) -> bool {
    evaluate_finding_challenge(input).authorizes_penalty()
}

assert_eq!(
    FindingChallengeReason::ReplayRunIncomplete.verdict(),
    FindingChallengeVerdict::Indeterminate,
);
assert_eq!(
    FindingChallengeReason::ReplayContradictionConfirmed.verdict(),
    FindingChallengeVerdict::Upheld,
);
```

## Guarantees

- `evaluate_finding_challenge` rechecks challenge and profile signatures,
  canonical finding bytes, content bindings, and the challenge-class matrix.
- Retained admission pins select profile and purchase authorities. Fresh signed
  authority status and the supplied evaluation time constrain lifecycle checks.
- `FindingChallengeAdjudication` derives its verdict from its reason.
  `authorizes_penalty` accepts only an adjudicated `Upheld` result.
- Inadmissible submissions produce no verdict. Unestablished authority or
  incomplete replay produces an `Indeterminate` adjudication where evaluable.

## Status

Implemented offline evaluator for digest mismatch, evidence invalidity, and
replay contradiction. It fetches nothing, executes no reproduction, reads no
clock, writes no state, and signs no outcome. The coordinator supplies retained
records and owns outcome signing, custody, and penalty application.
The crate declares no Cargo features and is unpublished (`publish = false`).

## Related

- [Architecture](ARCHITECTURE.md)
- [Finding artifact contract](../../../spec/PROTOCOL.md#647-finding-artifact-family)
- [Finding evidence verifier](../chio-finding-verifier/README.md)
- [Finding artifact types](../../economy/chio-finding/README.md)

[License](../../../LICENSE)
