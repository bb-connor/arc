# chio-web3

`chio-web3` defines and validates Chio's chain configuration, contract package,
identity binding, anchor, oracle, and settlement artifacts. Its public
settlement verifier checks a proof bundle against caller-owned trust pins and
independent chain observations. Runtime adapters consume these types.

## Usage

Sign and verify an identity-to-settlement-address binding locally:

```rust
use chio_web3::canonical::CanonicalBytes;
use chio_web3::crypto::Keypair;
use chio_web3::identity::{
    verify_web3_identity_binding, SignedWeb3IdentityBinding,
    Web3IdentityBindingCertificate, Web3KeyBindingPurpose,
    CHIO_KEY_BINDING_CERTIFICATE_SCHEMA,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let signer = Keypair::generate();
    let certificate = Web3IdentityBindingCertificate {
        schema: CHIO_KEY_BINDING_CERTIFICATE_SCHEMA.into(),
        chio_identity: "did:chio:example".into(),
        chio_public_key: signer.public_key(),
        chain_scope: vec!["eip155:8453".into()],
        purpose: vec![Web3KeyBindingPurpose::Anchor],
        settlement_address: "0x1111111111111111111111111111111111111111".into(),
        issued_at: 1_000, expires_at: 2_000, nonce: "binding-1".into(),
    };
    let signature = signer.sign_wrapped(
        CHIO_KEY_BINDING_CERTIFICATE_SCHEMA,
        &CanonicalBytes::from_serializable(&certificate)?,
    )?;
    let binding = SignedWeb3IdentityBinding { certificate, signature };
    verify_web3_identity_binding(&binding)?;
    Ok(())
}
```

This checks shape and a signature under the certificate's carried key.
It checks interval ordering; the caller separately checks current validity,
authorizes the key, and confirms ownership of the settlement address.

## Features

| Feature | Default | Effect |
| --- | --- | --- |
| `default` | Yes | Empty; all artifact and verification APIs are available. |
| `kani` | No | Declares a tooling feature; harness code is selected by `cfg(kani)`, independently of the Cargo feature. |

## Guarantees

`verify_anchor_inclusion_proof` checks identity and receipt signatures,
checkpoint signature, and Merkle inclusion after schema/binding validation.
Local anchor records require a separate external-chain observation.
`verify_public_settlement_proof` requires pinned bundle, capital, checkpoint,
and beneficiary keys plus runtime code hashes, independent chain-head context,
finality, public-witness, and dispute evidence. Oracle evidence, when carried,
must verify under a trusted oracle key.

## Status

Artifact validators and a synchronous public-settlement verifier are implemented.
The crate has no RPC client, transaction sender, or persistent receipt store.
`Web3QualificationMatrix` validates artifact shape; deployment acceptance and
contract promotion require independently collected operational evidence.

## Related

- [Architecture](ARCHITECTURE.md)
- [Protocol trust-control contract](../../../spec/PROTOCOL.md#9-trust-control-contract)
- [Anchor runtime](../chio-anchor/README.md)
- [Contract bindings](../chio-web3-bindings/README.md)
- [License](../../../LICENSE)
