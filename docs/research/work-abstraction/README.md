# Work as a reusable programming abstraction

Work composes owner-approved contracts, bounded delegation, native execution and independently checked results. Each authority retains its own keys, state and admission rules.

Start with the [integration inventory](INTEGRATION.md), [current-source map](CURRENT-STATE.md) and [pinned inputs](SOURCES.json). Public Work APIs and qualified work issuers remain planned; source inspection is not runtime qualification.

| Contract | Specification | Plan |
| --- | --- | --- |
| Ownership and acceptance | [Architecture](../../superpowers/specs/2026-10-03-agentic-work-kernel-design.md) | [Dependency order](INTEGRATION.md#implementation-order) |
| Local runtime | [Runtime](../../superpowers/specs/2026-10-03-work-runtime-design.md) | [W1](../../superpowers/plans/2026-10-03-work-runtime.md) |
| Separate owners | [Owner services](../../superpowers/specs/2026-10-03-work-owner-services-design.md) | [W2](../../superpowers/plans/2026-10-03-work-owner-services.md) |
| Protocols and SDKs | [Developer surface](../../superpowers/specs/2026-10-03-work-developer-surface-design.md) | [W3](../../superpowers/plans/2026-10-03-work-developer-surface.md) |
| Release acceptance | [Beta boundary](../../superpowers/specs/2026-10-03-agentic-work-kernel-design.md#beta-target-and-stopping-rule) | [W4](../../superpowers/plans/2026-10-03-work-beta-convergence.md) |

The non-recovery halves of W1.3 through W1.6 can implement only their named profile. Full semantic, custody, materialization and native-recovery behavior requires its qualified owner. Unknown effects never permit fresh dispatch, and issuer readback never relies on the coordinator index.
