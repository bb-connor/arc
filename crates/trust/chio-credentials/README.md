# chio-credentials

`chio-credentials` issues signed reputation credentials and bundles them into
Agent Passports. It provides holder presentations, verifier policies, portable
JWT projections, and financial passport authority APIs for Chio trust consumers.

## Usage

Create and validate an offline presentation challenge with explicit verifier
policy. A service must store and consume the challenge to enforce one-time use.

```rust
use chio_credentials::{
    create_passport_presentation_challenge, verify_passport_presentation_challenge,
    PassportPresentationOptions, PassportVerifierPolicy,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let challenge = create_passport_presentation_challenge(
        "https://verifier.example.com", "fixture-nonce", 1_000, 1_300,
        PassportPresentationOptions::default(),
        Some(PassportVerifierPolicy {
            min_receipt_count: Some(1), ..PassportVerifierPolicy::default()
        }),
    )?;
    verify_passport_presentation_challenge(&challenge, 1_100)?;
    assert_eq!(challenge.nonce, "fixture-nonce");
    Ok(())
}
```

## Features

| Feature | Default | Effect |
| --- | --- | --- |
| `fuzz` | Off | Exposes fuzz entry points and enables `arbitrary`. |
| `dudect` | Off | Enables `dudect-bencher` and the opt-in JWT timing test target. |

## Guarantees

- `verify_reputation_credential` binds issuer proof method, subject DID and score
  key, credential validity, and canonical signature. Issuer trust is policy input.
- `verify_agent_passport` verifies every credential and subject binding.
  `evaluate_agent_passport` accepts when at least one credential matches policy.
- Presentation verification binds the holder signature and, when supplied, the
  exact expected challenge. The native verifier does not consume replay state.
- `evaluate_financial_credentials` adds pinned issuer authority, verified policy,
  trusted time, lifecycle anchors, and source resolution to financial inspection.

## Status

Artifact and bounded OID4VCI/OID4VP profile helpers are implemented. HTTP endpoints
and durable storage live in consumers. Cross-issuer activation uses the signed
`chio.financial.cross-issuer-trust-pack.v1` under financial authority evaluation.
Settlement-reliability credential decoding is disabled because its proof
substrate is unavailable. Schema decoding and signature inspection alone do
not establish current admission, financial source completeness, or revocation.

## Related

- [Architecture](ARCHITECTURE.md)
- [Protocol Agent Passport](../../../spec/PROTOCOL.md#101-agent-passport)
- [DID identity](../chio-did/README.md)
- [Financial credential types](../../economy/chio-fincred/README.md)

## License

[Workspace license](../../../LICENSE)
