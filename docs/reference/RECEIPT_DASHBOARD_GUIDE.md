# Receipt Dashboard Guide

The Chio receipt dashboard is a React SPA that visualizes the kernel's receipt log. It is served directly by the trust-control axum server from the `dashboard/dist/` directory.

## Building the Dashboard

```bash
cd crates/products/chio-cli/dashboard
npm install
npm run test
npm run build
```

The build output lands in `crates/products/chio-cli/dashboard/dist/`. The trust-control server serves the `dist/` directory as a static catch-all after all API routes. No separate web server is needed.

The dashboard has no dependency on the `siem` feature flag. It communicates with the trust-control server's existing HTTP API.

## Accessing the Dashboard

Start the trust-control server, then open its HTTPS origin in a browser. The
dashboard session uses a `Secure` host-only cookie, so production access must
terminate TLS at the trust-control origin.

### Authentication

Configure `CHIO_TRUST_DASHBOARD_READ_TOKEN` with a credential distinct from
every service, administrator, workload, tenant, cluster, and relay credential.
The login form sends that credential once in the JSON body of
`POST /v1/dashboard/session`. The server returns a random, short-lived
`__Host-chio_dashboard` cookie with `Secure`, `HttpOnly`, `SameSite=Strict`,
and `Path=/`. Only the SHA-256 digest of the random session identifier is kept
in the bounded in-memory session table.

The browser sends the cookie with same-origin requests. It never writes the
credential to a URL, `sessionStorage`, `localStorage`, JavaScript authorization
header, or persistent application state. `DELETE /v1/dashboard/session` signs
out and clears the cookie. Sessions expire after 15 minutes and a service
restart requires a new login.

The dashboard session is read-only. It is accepted by the receipt query,
analytics, operator report, lineage, agent receipt, reputation comparison, and
optional relay observability endpoints. Mutation, administrative, signing,
issuance, revocation, budget-write, cluster, and evidence-export endpoints
continue to require their existing dedicated bearers. The static Proof Room
remains available without a dashboard session.

### Relay observability

The live pheromone relay exposes only
`GET /v1/chio/pheromone/observability`. To show that panel, configure both
`CHIO_TRUST_DASHBOARD_REPORT_ORIGIN` and a distinct
`CHIO_TRUST_DASHBOARD_REPORT_TOKEN`. Trust-control sends the relay token only to
the fixed observability path, disables redirects, bounds the response, requires
strict I-JSON, and validates the authoritative observability JSON Schema before
returning a no-store response.

The relay's alert, delivery, and assurance outputs are generated JSON files,
not live HTTP endpoints. Their dashboard panels remain hidden and their former
same-origin paths return 404 until a real read-only report service exists.

## Filtering Receipts

The left sidebar exposes the following filters:

- **Agent Subject**: hex-encoded Ed25519 public key; shows only receipts belonging to that agent's capability tokens
- **Tool Server**: exact match on the tool server name
- **Tool Name**: exact match on the tool name
- **Outcome**: `allow`, `deny`, `cancelled`, or `incomplete`
- **Since / Until**: Unix second timestamps for a time range

All filters map directly to the parameters on `GET /v1/receipts/query` (see `docs/RECEIPT_QUERY_API.md`). Changing any filter resets pagination to page 1. Results are shown 50 per page with Previous and Next pagination buttons backed by cursor-based pagination.

## Operator Report Summary

Above the receipt table, the dashboard renders a composed operator summary backed by `GET /v1/reports/operator`. It is not a client-side reconstruction over paged receipts. The summary cards surface:

- Activity totals for the filtered corpus
- Spend totals plus the top root subject in the attribution slice
- Budget pressure (`matchingGrants`, `nearLimitCount`, `exhaustedCount`)
- Compliance posture (`checkpointCoverageRate`, `lineageCoverageRate`, `uncheckpointedReceipts`)
- Settlement/export readiness (`pendingSettlementReceipts`, `failedSettlementReceipts`, proof completeness, and export-scope caveats)
- Shared remote evidence reference counts plus the latest referenced partner/share

This is the primary operator view for "is this agent/tool slice healthy and exportable right now?" The receipt table and detail panel remain the drill-down surface.

## Portable Reputation Comparison

When the **Agent Subject** filter is set, the dashboard also exposes a
portable comparison panel above the receipt table. Operators can upload a
passport JSON artifact and the dashboard will call
`POST /v1/reputation/compare/{subject_key}` on the trust-control service.

The panel renders:

- subject match vs mismatch between the live local subject key and the passport subject DID
- current local effective score and resolved tier
- optional relying-party acceptance state if the compared artifact already carries a verifier-evaluation result
- per-credential drift for composite score, reliability, delegation hygiene, and resource stewardship
- shared-evidence provenance for the local subject, including partner/share IDs,
  remote capability IDs, local anchor capability IDs, and local receipt counts

This keeps the browser on the same comparison contract already used by
`chio reputation compare --control-url ...`; the dashboard does not invent a
second local scoring path.

## Shared Evidence API Surface

Trust-control now also exposes `GET /v1/federation/evidence-shares`, which
returns the same shared-evidence report shape used inside operator reports and
portable reputation comparison. The CLI wrapper is:

```bash
chio trust evidence-share list --agent-subject <subject-hex> --json
```

This surfaces imported remote evidence references directly without merging
foreign receipts into native local receipt history.

## Receipt Detail Panel

Clicking any row in the receipt table opens a detail panel on the right. The panel shows:

- Decision badge (Allow / Deny / Cancelled / Incomplete)
- Tool server and tool name
- Formatted timestamp
- Full capability ID
- Financial metadata (if present): cost charged, budget remaining, total budget, delegation depth, and settlement status, all formatted from minor units
- Agent subject key (when attribution metadata is present)
- Cost over Time sparkline (per-day cost aggregated by the backend analytics API for the receipt subject)
- Delegation chain view (fetched from `GET /v1/lineage/{capability_id}/chain`)
- Raw tool call parameters
- Full receipt JSON

## Delegation Chain View

The `DelegationChain` component fetches from `GET /v1/lineage/{capability_id}/chain` and renders each `CapabilitySnapshot` in the chain from root to leaf. Each snapshot shows `subject_key`, `issuer_key`, `issued_at`, `expires_at`, `delegation_depth`, and the raw grants JSON. This allows operators to trace exactly how a capability was delegated and attenuated before reaching the agent.

## Budget Sparkline

The `BudgetSparkline` component is shown in the detail panel when the selected receipt has financial metadata. It is backed by `GET /v1/receipts/analytics?agentSubject=...&timeBucket=day`, using the receipt's attribution subject key (or the capability lineage fallback when attribution metadata is absent). The chart is rendered with lightweight inline SVG rather than a charting framework, which keeps the dashboard bundle small while still giving operators a useful spend trend.
