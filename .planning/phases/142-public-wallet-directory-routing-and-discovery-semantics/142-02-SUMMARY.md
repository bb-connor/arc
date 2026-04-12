# Summary 142-02

Defined public wallet-routing manifests and lookup behavior.

## Delivered

- added `WalletTransportMode`, `WalletRoutingGuardrails`,
  `PublicWalletRoutingManifestArtifact`, and
  `SignedPublicWalletRoutingManifest` in
  `crates/arc-core/src/identity_network.rs`
- published `docs/standards/ARC_PUBLIC_WALLET_ROUTING_EXAMPLE.json`
- required HTTPS routing endpoints, signed request objects, replay anchors,
  and all supported transport modes

## Result

Wallet routing is now a replay-safe, reviewable manifest contract instead of
ambient directory trust.
