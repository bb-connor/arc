# Phase 217 Context

The repo drifted into an ARC-side `product-surface` direction that hardcoded
Mercury and ARC-Wall into generic ARC crates. This phase restores the product
boundary by removing those ARC-side entrypoints and returning product packaging
ownership to the Mercury and ARC-Wall app layers.

Non-goals:
- do not widen ARC generic crates with replacement product packaging logic
- do not merge Mercury and ARC-Wall into one ARC-owned shell
- do not change Mercury or ARC-Wall app semantics in this phase
