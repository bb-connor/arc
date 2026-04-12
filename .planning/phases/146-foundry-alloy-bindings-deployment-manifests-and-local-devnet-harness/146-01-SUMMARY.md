# Summary 146-01

Added reproducible build and deployment tooling for the official contract
package.

## Delivered

- pinned the Solidity package tooling in `contracts/package.json` with `solc`,
  `ethers`, and `ganache`
- added the compiler entrypoint in `contracts/scripts/compile.mjs` and
  published compiled artifacts under `contracts/artifacts/`
- published bounded chain templates in
  `contracts/deployments/base-mainnet.template.json` and
  `contracts/deployments/arbitrum-one.template.json`

## Result

The official contract family can now be rebuilt and re-packaged from source
instead of being implied by research prose or hand-maintained ABI notes.
