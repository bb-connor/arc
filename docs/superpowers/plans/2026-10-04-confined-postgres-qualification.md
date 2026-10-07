# Confined PostgreSQL qualification

> Execute inline with Superpowers executing-plans and test-driven-development. No subagents. This is Task 4 of the PR 1173 production readiness plan.

The existing PostgreSQL adapter opens a database connection and starts a Tokio
runtime inside the native cage. The shipped profile deliberately denies those
ambient operations. Its response-loss fixture also launches another process
inside the cage. Both failures occur before the intended ownership and recovery
qualification can establish its claims.

The resource implementation and worker lease API remain authoritative. Move the
TLS PostgreSQL connection to an authenticated host adapter, and execute the
existing static `chio-broker-mcp` proxy in the cage. Reuse prepared admission,
broker custody, original invocation identity, native launch policy and receipts.

## Architecture and boundaries

- Expose the existing bounded loopback HTTPS adapter interface from
  `chio-secret-broker::host_https`. This interface belongs to the trusted host;
  its bearer authenticates the broker. It grants no worker authority by itself.
  Preserve its private-key/credential checks, exact POST route, message bounds,
  constant-time bearer comparison and bounded connection concurrency.
- Add a fixed `kernel_mcp_tool_call` payload mapping to the existing host
  preparer. It constructs `name`, `arguments` and kernel caller metadata from
  the installed route and the original parent capability. Workers cannot supply
  the caller binding. Construct and sign the body inside the existing durable
  preparation callback where the parent capability is available.
- Keep one tool per broker route and native manifest. The example uses explicit
  server identifiers `jobs-task`, `jobs-complete`, `jobs-renew`,
  `jobs-admin-assign`, `jobs-admin-release` and `jobs-admin-inspect`. This reuses
  the existing route model without extending the broker's authority surface.
  Children receive only the three worker routes. The public PostgreSQL worker
  methods, argument types and lease semantics remain unchanged.
- Add a host HTTPS mode to the Rust `agent_jobs` example. A private configuration
  fixes the tenant, worker/operator role and endpoint credentials. The shared
  HTTPS server authenticates requests before the resource receives JSON. The
  existing typed resource dispatcher validates the request and lease owner.
  Database credentials remain in this host process; neither the native proxy,
  process connection descriptor nor model receives them.
- Reuse the existing native consumer service helper to provision six real
  brokers and static proxy manifests. It is qualification orchestration, with
  fixture keys. The production broker, admission and cage are exercised.
- Retain actual SIGKILL and two queued PostgreSQL jobs. A test-only resource
  cut point records the committed first assignment, withholds its HTTPS reply,
  and closes that exchange after the orchestrator kills the host. The adapter
  remains available for inspection and an explicit new-intent control. Recovery
  must reuse the retained prepared envelope and must not consume the second job.

## Rejected alternatives

Granting socket or process creation rights to the generic cage would expand
every consumer's authority. Replacing PostgreSQL with an in-memory resource
would not qualify durability. A new admission system or a multi-tool broker
protocol would add unnecessary security surface. Each route already has the
required capability, quota, recovery and receipt machinery.

## Implementation and acceptance

- [x] Add failing payload-binding controls: worker-selected metadata cannot
  replace the original capability hash; tool identity comes from the installed
  route; JSON and model mappings preserve their existing output.
- [x] Implement the mapping and expose the existing HTTPS adapter interface with
  documentation of its trusted-host contract. Keep errors typed and redacted.
- [x] Implement the PostgreSQL host adapter as a separate example module. Use a
  bounded async deadline and strict duplicate-aware input parsing. Preserve
  typed lease-loss/conflict results; uncertain database failures must not imply
  that no effect occurred.
- [x] Replace native gateway launch with broker fixture composition in the two
  qualification drivers. Save the actual prepared request for response binding
  and recovery. Verify original signed receipts and unchanged caller identity.
- [x] Add credential-isolation, forged-caller, route-denial and cut-point
  controls. Inspect private versus shareable evidence for secret leakage.
- [x] Run the PostgreSQL worker API, payload tests, example/CLI Clippy and
  protocol workflow contract tests. Update CI to build and provision the existing
  prepared native broker fixture.
- [ ] Run both real trajectories on Linux x86_64 with TLS PostgreSQL, enforced
  native confinement and actual host termination. Require the same tenant,
  owner and fence checks, one original claim delivery, unchanged pending job
  after recovery, and a successful explicit new-intent control.
- [ ] Review the full change against the production readiness spec. Retain every
  unsuccessful attempt and bind final evidence to the exact committed source.

The profile and launch-thread follow-up is recorded in the parent readiness
plan. Implementation and local boundary checks are complete. Final native
trajectory acceptance remains tied to the exact x86 candidate and its public
reports; earlier failed attempts do not satisfy those two remaining items.
