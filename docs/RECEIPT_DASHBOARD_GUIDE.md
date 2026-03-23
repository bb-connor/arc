# Receipt Dashboard Guide

The PACT receipt dashboard is a React SPA that visualizes the kernel's receipt log. It is served directly by the trust-control axum server from the `dashboard/dist/` directory.

## Building the Dashboard

```bash
cd crates/pact-cli/dashboard
npm install
npm run build
```

The build output lands in `crates/pact-cli/dashboard/dist/`. The trust-control server serves the `dist/` directory as a static catch-all after all API routes. No separate web server is needed.

The dashboard has no dependency on the `siem` feature flag. It communicates with the trust-control server's existing HTTP API.

## Accessing the Dashboard

Start the trust-control server, then open `http://localhost:<port>/` in a browser. The server port is set in your PACT configuration.

### Authentication

All API calls from the dashboard require a Bearer token. The token is read in this order:

1. `sessionStorage` key `pact_token` (set from a previous visit)
2. URL query parameter `?token=<value>`

When a token is found in the URL it is moved to `sessionStorage` and removed from the URL bar (using `window.history.replaceState`) to prevent it from appearing in browser history or the `Referer` header.

Pass your service token on the initial URL:

```
http://localhost:7391/?token=my-service-token
```

After the first load the token is stored in `sessionStorage` for the session. Closing the tab clears it.

## Filtering Receipts

The left sidebar exposes the following filters:

- **Agent Subject**: hex-encoded Ed25519 public key; shows only receipts belonging to that agent's capability tokens
- **Tool Server**: exact match on the tool server name
- **Tool Name**: exact match on the tool name
- **Outcome**: `allow`, `deny`, `cancelled`, or `incomplete`
- **Since / Until**: Unix second timestamps for a time range

All filters map directly to the parameters on `GET /v1/receipts/query` (see `docs/RECEIPT_QUERY_API.md`). Changing any filter resets pagination to page 1. Results are shown 50 per page with Previous and Next pagination buttons backed by cursor-based pagination.

## Receipt Detail Panel

Clicking any row in the receipt table opens a detail panel on the right. The panel shows:

- Decision badge (Allow / Deny / Cancelled / Incomplete)
- Tool server and tool name
- Formatted timestamp
- Full capability ID
- Financial metadata (if present): cost charged, budget remaining, total budget, delegation depth, and settlement status, all formatted from minor units
- Cost over Time sparkline (per-day cost aggregated from the last 200 receipts for the capability's agent)
- Delegation chain view (fetched from `GET /v1/lineage/{capability_id}/chain`)
- Raw tool call parameters
- Full receipt JSON

## Delegation Chain View

The `DelegationChain` component fetches from `GET /v1/lineage/{capability_id}/chain` and renders each `CapabilitySnapshot` in the chain from root to leaf. Each snapshot shows `subject_key`, `issuer_key`, `issued_at`, `expires_at`, `delegation_depth`, and the raw grants JSON. This allows operators to trace exactly how a capability was delegated and attenuated before reaching the agent.

## Budget Sparkline

The `BudgetSparkline` component is shown in the detail panel when the selected receipt has financial metadata. It fetches up to 200 receipts for the same capability's agent via `GET /v1/agents/{subject_key}/receipts` and aggregates `cost_charged` by calendar day (UTC). The resulting time series is rendered as a line chart using recharts. The sparkline gives a visual cost-over-time view without requiring a separate analytics backend.

The sparkline requires no `siem` feature flag; it is computed client-side from the existing receipt query API.
