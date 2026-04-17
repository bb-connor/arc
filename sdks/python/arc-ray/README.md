# arc-ray

Ray integration for the [ARC protocol](../../../spec/PROTOCOL.md). Wraps
`ray.remote` and Ray actors so every remote task invocation and every
actor method call is evaluated by the ARC sidecar kernel for
capability-scoped authorisation, guard enforcement, and signed receipts.

## Install

```bash
uv pip install arc-ray
# or
pip install arc-ray
```

The package depends on `arc-sdk-python`, `ray[default]>=2.10,<3`, and
`pydantic>=2.5`.

## Two surfaces

### 1. `@arc_remote` -- per-call capability check on Ray tasks

```python
import ray
from arc_ray import arc_remote

# Mint a capability token on the driver (via your arc-sdk client).
capability_id = "cap-researcher-1"

@arc_remote(
    scope="tools:search",
    capability_id=capability_id,
    tool_server="tools-srv",
)
def search(query: str) -> list[dict]:
    return search_engine.search(query)

# Same .remote(...) / ray.get(...) contract as @ray.remote.
result = ray.get(search.remote("latest papers"))
```

Every call to `search.remote(...)` first evaluates the capability via
the node-local ARC sidecar (default `http://127.0.0.1:9090`). On a deny
verdict the worker raises `PermissionError`; Ray propagates that
through `ray.get(...)` so the driver sees a `RayTaskError` whose
underlying exception is a `PermissionError`. The caller can
`except PermissionError` without depending on any ARC-specific type.

Every keyword argument supported by `ray.remote` (`num_cpus`,
`num_gpus`, `resources`, `runtime_env`, `max_calls`, `max_retries`, ...)
passes straight through.

### 2. `ArcActor` -- standing grants for long-lived Ray actors

```python
import ray
from arc_ray import ArcActor, StandingGrant
from arc_sdk import ArcClient
from arc_sdk.models import ArcScope, Operation, ToolGrant


async def mint_search_grant() -> StandingGrant:
    arc = ArcClient()
    scope = ArcScope(
        grants=[
            ToolGrant(
                server_id="tools-srv",
                tool_name="search",
                operations=[Operation.INVOKE],
            ),
        ],
    )
    token = await arc.create_capability(
        subject="agent:researcher", scope=scope, ttl_seconds=3600
    )
    return StandingGrant(token=token, tool_server="tools-srv")


@ray.remote
class ResearchAgent(ArcActor):
    def __init__(self, *, grant: StandingGrant) -> None:
        super().__init__(standing_grant=grant)

    @ArcActor.requires("tools:search")
    def search(self, query: str) -> list[dict]:
        return search_engine.search(query)

    @ArcActor.requires("tools:browse")
    def browse(self, url: str) -> str:
        return fetch_page(url)


grant = await mint_search_grant()
agent = ResearchAgent.remote(grant=grant)

# In-scope -- allowed.
hits = ray.get(agent.search.remote("quantum"))

# Out-of-scope -- denied. `browse` requires `tools:browse`, but the
# standing grant only authorises `tools:search`, so the short-circuit
# subset check raises PermissionError without even calling the sidecar.
try:
    ray.get(agent.browse.remote("https://example.com"))
except PermissionError as err:
    print(err.arc_error.reason)  # "scope_exceeds_standing_grant"
```

`ArcActor.__init__` accepts several construction forms:

* `standing_grant=` -- a pre-minted `StandingGrant`.
* `standing_grants=[grant_a, grant_b, ...]` -- a list of grants merged
  into a single standing scope (union of all tool grants). The first
  grant's token id is the canonical capability id on the sidecar call;
  the remaining ids are preserved in `arc_grant.metadata["delegated_capability_ids"]`
  for audit.
* `token=` + optional `scope=` -- ergonomic shortcut for the
  single-grant case. When `scope` is narrower than `token.scope`, the
  standing grant adopts the narrower scope (cryptographic attenuation
  still requires `StandingGrant.attenuate` with a live ARC client).

### Attenuation for supervisor / worker patterns

A supervisor actor can delegate narrower scopes to worker actors
using `StandingGrant.attenuate`:

```python
@ray.remote
class Supervisor(ArcActor):
    def __init__(self, *, grant: StandingGrant) -> None:
        super().__init__(standing_grant=grant)

    async def spawn_researcher(self) -> ray.ObjectRef:
        narrow_scope = ArcScope(grants=[
            ToolGrant(
                server_id="tools-srv",
                tool_name="search",
                operations=[Operation.INVOKE],
            ),
        ])
        child_grant = await self.arc_grant.attenuate(
            self._arc_client, new_scope=narrow_scope
        )
        return Researcher.remote(grant=child_grant)
```

The attenuation hits the ARC kernel to mint a fresh child capability
token. `new_scope` must be a subset of the parent's scope; anything
broader raises `ArcValidationError` before the sidecar round-trip.

## Error propagation

Denied calls raise `PermissionError`; the underlying `ArcRayError`
(with guard, reason, receipt id, decision payload) is attached as
`err.arc_error`. Ray wraps worker exceptions in `RayTaskError`; the
wrapper preserves the underlying type so `except PermissionError`
idioms work at the driver unchanged.

The short-circuit subset check on the standing grant runs **before**
the sidecar call. Methods whose `requires(...)` scope is not a subset
of the actor's standing scope are denied with
`guard="StandingGrantSubsetGuard"` without any network round-trip. This
keeps the common "agent tried a tool it was never granted" case fast
and predictable. Sidecar-path denies (where the grant admits the
scope but a runtime guard rejects the specific call) carry the
sidecar's own `guard` / `reason` / `receipt_id`.

## Testing

`arc_ray` works with `arc_sdk.testing.MockArcClient` so tests can
exercise the allow/deny path without a live sidecar. See
`tests/test_arc_remote.py` and `tests/test_arc_actor.py` for
fixtures. The test suite replaces Ray's scheduler with a lightweight
fake that calls decorated functions in-process on `.remote(...)`;
the ARC enforcement path is identical under the real scheduler, but
the fake keeps the suite fast and deterministic. Set the
`ARC_RAY_USE_REAL=1` environment variable to import the real
`ray` package instead (the cluster is still not started -- tests
only exercise the wrapper logic).

## Status

* **Phase 17.4 (this crate)**: `@arc_remote`, `ArcActor`,
  `StandingGrant`, attenuation, error propagation.
* **Future**: `ArcServeMiddleware` for Ray Serve deployments,
  `ReceiptAggregator` for scatter/gather receipt collection,
  placement-group trust zones, object store governance. See
  `docs/protocols/RAY-INTEGRATION.md` for the full vision.
