# chio-control-plane

`chio-control-plane` packages Chio's trust-control service, client helpers, and
shared runtime wiring for clustered authority, receipt, revocation, and budget
state.

Use this crate when you need the trust-control layer behind `chio trust serve`
or you are wiring a distributed Chio deployment instead of a single local
sidecar.

Cluster traffic uses dedicated per-node Ed25519 membership identities. Each
node requires a strict private seed, an exact normalized URL-to-public-key
membership map, and a durable replay database. Internal routes reject general
service and administrative bearers. Membership proves transport origin only;
privileged authority operations still require the workload or administrator
role configured for that operation.

## Dashboard read boundary

The browser dashboard does not receive a service, administrator, workload,
tenant, cluster, or relay bearer. Configure a distinct
`CHIO_TRUST_DASHBOARD_READ_TOKEN`; the browser submits it once to
`POST /v1/dashboard/session` and receives a short-lived, host-only,
`HttpOnly` session cookie. Dashboard sessions are bounded in memory, expire
after 15 minutes, and are invalid after a trust-control restart.

The session is accepted only by the receipt query, receipt analytics, operator
report, lineage, agent receipt, reputation comparison, and relay observability
read surfaces. It is not accepted by mutation, administrative, signing,
issuance, revocation, budget-write, cluster, or evidence-export endpoints.

Relay observability is optional. Configure both
`CHIO_TRUST_DASHBOARD_REPORT_ORIGIN` and
`CHIO_TRUST_DASHBOARD_REPORT_TOKEN` to proxy the relay's live
`GET /v1/chio/pheromone/observability` endpoint. The origin must use HTTPS;
HTTP is limited to explicit loopback test mode. The server-side relay token
must be distinct from every other credential. Alert and assurance report files
are generated artifacts, not live relay HTTP routes, so trust-control does not
expose those paths.
