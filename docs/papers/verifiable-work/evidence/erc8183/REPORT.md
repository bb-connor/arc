# ERC-8183 comparison: executable local evidence

ERC-8183 already supports the central economic counterexample to an exclusive Chio claim: an independently funded child can be paid even when its parent is refunded. The pinned upstream implementation also supports approved partial payments that survive rejection of the remaining work. These results do not establish a novel escrow or subcontracting primitive for Chio.

The unmodified upstream suite passed **76 tests**. The added comparison passed **20 tests: 12 ERC-8183 and 8 Chio**, with zero failures or skips. Both ran actual compiled contract bytecode in Foundry's local Cancun EVM. Upstream uses its ERC1967 proxy and original transient-storage reentrancy guard. No upstream Solidity was patched.

## Pins and method

- [ERC-8183 specification](https://github.com/ethereum/ERCs/blob/365b4c02879f3e882b91281d42b4f57b406205e9/ERCS/erc-8183.md), Draft, created 2026-02-25.
- [Actual upstream implementation](https://github.com/erc-8183/base-contracts/tree/142e669c1fd318486a4628395b629f033654dd06), commit `142e669c1fd318486a4628395b629f033654dd06`, MIT license retained in `provenance/`.
- Chio `ChioWorkClaimEscrow.sol` from clean source at `7755d3762baa5e0fda0d171835a9000c26de9033`, SHA-256 `b1def783516523cf58c2e60f9d541cdcc47ec07f80e9662e01f88c8cb77e1df9`. A source snapshot and license are retained.
- Solidity `0.8.28+commit.7893614a`, Cancun, optimizer 200 runs; official Foundry `v1.8.4`, commit `50af4efe189dc64bad2b75ed6990b835de66c4ae`. The official release download digest was verified. Exact recursive submodule pins and compiler hash are in `provenance/source-pins.json`.

Both fixtures use the same upstream `MockUSDC`, zero fees, a buyer with 100 raw token units, and an intermediary with a separate 60 units for the child. Buyer, intermediary, worker, and evaluator are distinct addresses. The evaluator is trusted to decide acceptance in both systems; an EOA sends ERC-8183 evaluation transactions and signs Chio decisions. The economic cases assume an honest, available token and no administrative interference. Parent and child are separate jobs/allocations with no automatic linkage in either escrow. Their different native deadline rules are exercised explicitly.

## Results

Balances are `(buyer, intermediary, worker, escrow)`.

| Scenario | ERC-8183 | Chio |
| --- | --- | --- |
| Parent 100 and child 60 succeed | `(0,100,60,0)` | `(0,100,60,0)` |
| Child paid, then parent rejected | `(100,0,60,0)` | `(100,0,60,0)` |
| Parent expires/refunds before later child acceptance | `(100,0,60,0)` | `(100,0,60,0)` |
| One 100-unit balance funds two 60-unit jobs | Second funding reverts | Second funding reverts |
| Intermediary has no working capital; parent 100 is unsettled | Cannot fund child 60 | Cannot fund child 60 |
| Evaluator unavailable after submission | Refund after expiry plus 1-hour grace | Refund after `refundAfter` |
| Single 100-unit job: approve 60, then reject remaining work | Provider retains 60; buyer refunded 40 | Fixed-price allocation has no partial-settlement entrypoint |

The intermediary starts with 60 of its own capital. A successful parent pays it 100, yielding a net 40 increase; parent failure loses its 60. Neither protocol turns 100 units of backing into a full 100-unit parent refund plus an additional 60-unit child payment.

ERC-8183's [partial-claim implementation](https://github.com/erc-8183/base-contracts/blob/142e669c1fd318486a4628395b629f033654dd06/contracts/ERC8183.sol#L921-L1039) and [remaining-balance refund](https://github.com/erc-8183/base-contracts/blob/142e669c1fd318486a4628395b629f033654dd06/contracts/ERC8183.sol#L839-L884) are a stronger baseline than a hand-written minimal escrow. Its [authorization extension](https://github.com/erc-8183/base-contracts/blob/142e669c1fd318486a4628395b629f033654dd06/contracts/ERC8183WithAuthorization.sol) already supports EIP-712 relayable operations; its 25 upstream tests passed. Courier submission is therefore also shared prior art.

## Demonstrated differences and their limits

Chio records acceptance as `Payable` before withdrawal. The test leaves the child's 60 in escrow, refunds the parent, pauses new funding, removes the token/verifier from allowlists, advances time 100 days, and successfully withdraws the earned payment. ERC-8183's normal completion pays immediately in the acceptance transaction. Immediate payment already preserves the provider's proceeds; a separate `Payable` state is a policy/architecture distinction, not proof of a stronger final economic outcome.

Chio rejects new acceptance after `resolveBy`, even before refund is executed. In the pinned ERC-8183 implementation, completion can still win after the grace period if no refund transaction has executed; refund first prevents later completion. ERC-8183 refunds also fail while its admin pause is active. These are implementation-specific state-machine choices. ERC-8183 permits evaluator contracts, hooks, and payout receivers; this experiment does not prove that a suitable extension cannot implement Chio's chosen rules.

The upstream admin can also upgrade the proxy, alter fees, detach hooks, and withdraw while paused. Those are source-observed powers, not attack experiments or requirements of every ERC-8183 implementation. The economic comparison held those powers inactive. The standard and pinned repository differ in details, including the repository's grace period and milestone extension; findings about this repository must not be generalized to the whole standard.

## Reproduction and scope

Run `python3 reproduce.py --forge /path/to/forge --label rerun` from this artifact. It clones the fixed upstream commit if absent, verifies the commit and tracked diff, fetches pinned submodules, writes path-specific Foundry configuration, and runs the upstream suite plus comparison traces and JSON. `REPORT.json` maps exact test names to results. `logs/verified-*` contains the final raw outputs, commands, exit statuses, and timing. `SHA256SUMS` identifies the evidence files.

Earlier failures remain recorded: an x86-64 binary on ARM64, a command-wrapper argument-order error, an expectation placed before the Chio test helper's read call, and a Foundry config filename rejection. The final reproduction command exited 0 after these harness/tooling corrections. Contract source was never changed to obtain a pass. The compact archive was also extracted to a different directory and its reproduction script passed the same 76 upstream and 20 comparison tests (`logs/portable-reproduction.log`, exit 0).

This is local bytecode evidence with synthetic work commitments and a mock token, not a security audit, live deployment, chain-finality test, independent-operator trial, or demonstration of substantive work verification. No wall-clock or gas superiority is claimed. Any defensible Chio contribution must be narrower, such as a specified portable artifact profile and its independently verified interoperability, rather than claiming that funded jobs, evaluator-gated settlement, or surviving child payments were absent from prior art.

The upstream specification is retained byte-for-byte in `provenance/erc-8183.md.gz`.
Use `gzip -dc provenance/erc-8183.md.gz` to extract it. The specification pin is
the SHA-256 of the decompressed bytes; `SHA256SUMS` identifies the compressed
representation. The artifact checker verifies both against the upstream source pin.
