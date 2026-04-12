# ARC Web3 Contracts

This package is the phase `145` realization of ARC's official web3 contract
family:

- `ArcRootRegistry`
- `ArcEscrow`
- `ArcBondVault`
- `ArcIdentityRegistry`
- `ArcPriceResolver`

The source shapes come from
`docs/research/ARC_WEB3_CONTRACT_ARCHITECTURE.md`, but the implementation
tightens three research-era gaps deliberately:

1. RFC6962 proof verification needs `leafIndex` and `treeSize`. The research
   interface examples omitted those fields in the public methods, so the
   contracts add `*Detailed` overloads and make the under-specified methods
   revert fail closed.
2. Signature-based escrow release must bind `escrowId`, `settledAmount`, and
   chain context into the signed payload. Verifying a bare `receiptHash` would
   leave the amount under-specified.
3. Root publication supports explicit delegate publishers so ARC can authorize
   automation or HA anchoring infrastructure without widening operator trust.

The compiled interface artifacts under `contracts/artifacts/interfaces/` are
also the canonical binding input for `crates/arc-web3-bindings/`. ARC now
derives the Rust Alloy surface from those compiled interface artifacts instead
of maintaining a second handwritten contract interface inventory.

The money-handling boundary is intentionally narrow:

- `ArcBondVault` locks collateral on-chain and preserves reserve requirement
  metadata from the signed ARC bond artifact for parity checks; it does not
  create a second on-chain reserve ledger.
- `ArcPriceResolver` is an auxiliary on-chain feed reader for bounded contract
  parity and review. The canonical runtime FX authority remains the off-chain
  `arc-link` receipt-evidence path.

Compile locally with:

```bash
pnpm --dir contracts install
pnpm --dir contracts compile
```

Run the local qualification harness with:

```bash
pnpm --dir contracts devnet:smoke
```

That deploys the full contract family plus mocks to an ephemeral Ganache
devnet, exercises the core fail-closed paths, and writes deployment and
qualification reports under `contracts/deployments/` and `contracts/reports/`.

Run the reviewed-manifest promotion qualification with:

```bash
./scripts/qualify-web3-promotion.sh
```

That compiles the contract package, uses
`contracts/deployments/local-devnet.reviewed.json`, generates a local approval
artifact, proves CREATE2 address reproducibility across fresh local devnets,
and verifies that bad approvals and failed promotions emit explicit rollback
artifacts.

The bounded promotion runner itself is:

```bash
node contracts/scripts/promote-deployment.mjs \
  --manifest contracts/deployments/local-devnet.reviewed.json \
  --approval target/web3-promotion-qualification/run-a/approval.json \
  --output-dir target/web3-promotion-qualification/manual-run \
  --local-devnet \
  --rollback-on-failure
```

For non-local rollout the same runner requires operator-owned `--rpc-url`,
`--deployer-key`, a reviewed manifest derived from the shipped `*.template.json`
files, and an approval artifact that binds the exact manifest hash, release id,
deployment policy id, predeployed CREATE2 factory, and salt namespace.
