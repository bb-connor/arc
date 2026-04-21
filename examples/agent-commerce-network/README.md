# Agent Commerce Network

Governed service procurement between a buyer and provider using Chio for
capability-based access control, budget enforcement, and receipt signing.

## Scenario

Lattice Platform Security needs a security review for their payments API.
Vanguard Security provides reviews via an MCP tool server. Chio governs every
interaction: the buyer's API sits behind `arc api protect`, the provider's
MCP server sits behind `arc mcp serve-http`, and trust-control tracks
budgets, receipts, and capabilities.

A procurement agent (OpenAI Agents SDK) reasons about which review scope
to request, evaluates the quote, creates a governed job, and handles
approval if the price exceeds the threshold.

## Architecture

```
arc trust serve                     capability authority, budget store
arc mcp serve-http                  kernel-mediated provider MCP tools
arc api protect                     buyer API sidecar (receipt signing)
buyer/app.py                        FastAPI procurement service
provider/review_server.py           MCP tool server (quote, execute, dispute)
orchestrate.py                      procurement agent entry point
```

## Running

```bash
cargo build --bin arc
./smoke.sh
```

Set `OPENAI_API_KEY` for live agent reasoning. Without it, runs a
deterministic fallback flow (CI mode).

## What Chio Governs

- **Budget limits** on capability grants (`maxTotalCost`, `maxCostPerInvocation`)
- **Receipt signing** for every buyer API call (via `arc api protect`)
- **Guard policies** on provider MCP tools (via `arc mcp serve-http`)
- **Budget tracking** via trust-control's split budget endpoints (`/v1/budgets/authorize-exposure`, `/v1/budgets/release-exposure`, `/v1/budgets/reconcile-spend`)
- **Financial reports**: exposure ledger, settlement reconciliation

## Structure

```
commerce_network/           shared package
  arc.py                    Chio clients (MCP, trust-control)
  agents.py                 procurement agent (Agents SDK / Anthropic)
  verify.py                 bundle verification
buyer/
  app.py                    FastAPI procurement service
  policy.yaml               Chio HushSpec policy
  openapi.yaml              API spec with x-chio-* metadata
  run-sidecar.sh            arc api protect wrapper
provider/
  review_server.py          MCP tool server
  policy.yaml               Chio HushSpec policy
  run-edge.sh               arc mcp serve-http wrapper
contracts/                  JSON contract templates
orchestrate.py              entry point
smoke.sh                    smoke test
```
