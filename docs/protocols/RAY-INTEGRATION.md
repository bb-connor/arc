# Ray Integration: Distributed Agent Swarm Security

> **Status**: Tier 3 -- proposed April 2026
> **Priority**: Exploratory -- Ray's distributed compute model aligns with
> agent swarm architectures. `ray.remote()` tasks and actors become
> capability-scoped execution units. Relevant to the chiodome vision of
> agent congregations as distributed fiscal entities.

## 1. Why Ray

Ray is a distributed compute framework designed for scaling Python
applications across clusters. Its actor model and task parallelism make it
the natural substrate for agent swarms -- many agents running concurrently,
each with their own tool access patterns, resource budgets, and trust levels.

Ray Serve handles inference serving. Ray Train handles distributed training.
Ray Data handles distributed data processing. All of these can be points
where agents invoke tools or access sensitive resources.

### ARC Value in the Ray Model

| Ray Concept | ARC Mapping | Value |
|-------------|-------------|-------|
| `@ray.remote` task | Capability-scoped tool call | Each remote task checked before execution |
| Actor | Long-lived agent with standing capability | Actor lifecycle matches capability grant lifetime |
| Actor method call | Tool invocation within actor scope | Per-method capability evaluation |
| Object store | Data transfer governance | Large objects (models, datasets) require read/write capabilities |
| Placement group | Trust zone | Actors in the same placement group share trust boundary |
| Ray Serve deployment | Tool server | Serve endpoints governed by ARC |

## 2. Architecture

### 2.1 Sidecar per Ray Node

Each Ray node runs an ARC sidecar. Ray tasks and actors on that node call
the local sidecar:

```
Ray Cluster
+------------------------------------------------------------------+
|  Head Node                                                       |
|  +-------------------+  +------------------------------------+   |
|  | Ray GCS / Driver  |  | ARC Sidecar (:9090)                |   |
|  |                   |  | Policy sync | Receipt aggregation   |   |
|  +-------------------+  +------------------------------------+   |
+------------------------------------------------------------------+
|  Worker Node 1                                                   |
|  +-----------------+  +-------+  +----------------------------+  |
|  | Agent Actor 1   |  | Agent |  | ARC Sidecar (:9090)        |  |
|  | cap: search,    |  | Act 2 |  | Evaluate | Guard | Receipt |  |
|  |      browse     |  | cap:  |  +----------------------------+  |
|  +-----------------+  | write |                                  |
|                       +-------+                                  |
+------------------------------------------------------------------+
|  Worker Node 2                                                   |
|  +-----------------+  +-------+  +----------------------------+  |
|  | Agent Actor 3   |  | Agent |  | ARC Sidecar (:9090)        |  |
|  | cap: analyze    |  | Act 4 |  | Evaluate | Guard | Receipt |  |
|  +-----------------+  | cap:  |  +----------------------------+  |
|                       | trade |                                  |
|                       +-------+                                  |
+------------------------------------------------------------------+
```

### 2.2 Alternative: ARC as a Ray Actor

For lighter deployments, ARC can run as a named Ray actor instead of a
per-node sidecar:

```python
import ray
from arc_ray import ArcKernelActor

# Deploy ARC as a detached named actor
arc_kernel = ArcKernelActor.options(
    name="arc-kernel",
    lifetime="detached",
    num_cpus=0.5,
).remote(policy_path="/etc/arc/policy.yaml")
```

## 3. Integration Model

### 3.1 Remote Task Wrapper (`@arc_remote`)

```python
import ray
from arc_ray import arc_remote

@arc_remote(scope="tools:search", budget={"max_calls": 100})
def search(query: str) -> list[dict]:
    """Remote task with ARC capability enforcement."""
    return search_engine.search(query)

# Usage -- same as ray.remote but ARC-governed
result = ray.get(search.remote("latest papers"))
```

Implementation:

```python
def arc_remote(scope: str, guards: list[str] | None = None, budget: dict | None = None, **ray_kwargs):
    """Decorator combining @ray.remote with ARC capability enforcement."""

    def decorator(fn):
        @ray.remote(**ray_kwargs)
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            from arc_sdk import ArcClient
            arc = ArcClient()  # connects to node-local sidecar

            verdict = arc.evaluate_sync(
                tool=fn.__name__,
                scope=scope,
                guards=guards,
                budget=budget,
            )

            if verdict.denied:
                raise PermissionError(f"ARC denied {fn.__name__}: {verdict.reason}")

            result = fn(*args, **kwargs)
            arc.record_sync(verdict=verdict)
            return result

        # Preserve ray.remote interface
        wrapper._arc_scope = scope
        return wrapper

    return decorator
```

### 3.2 Actor-Level Capabilities (`ArcActor`)

Actors are long-lived -- they get standing capability grants that last
for the actor's lifetime:

```python
import ray
from arc_ray import ArcActor

@ray.remote
class ResearchAgent(ArcActor):
    """Agent actor with ARC-scoped capabilities."""

    arc_scope = "agent:researcher"
    arc_capabilities = ["tools:search", "tools:browse", "tools:summarize"]
    arc_budget = {"max_calls": 500, "max_cost_usd": 5.00}

    def __init__(self):
        super().__init__()  # Acquires standing grant from ARC
        self.search_engine = SearchEngine()

    @ArcActor.requires("tools:search")
    def search(self, query: str) -> list[dict]:
        """Each method call checks against the actor's granted scope."""
        return self.search_engine.search(query)

    @ArcActor.requires("tools:browse")
    def browse(self, url: str) -> str:
        return fetch_page(url)

    @ArcActor.requires("tools:summarize")
    def summarize(self, text: str) -> str:
        return summarizer.run(text)
```

Implementation of `ArcActor`:

```python
class ArcActor:
    """Base class for Ray actors with ARC capability grants."""

    arc_scope: str = ""
    arc_capabilities: list[str] = []
    arc_budget: dict = {}

    def __init__(self):
        from arc_sdk import ArcClient
        self._arc = ArcClient()
        self._grant = self._arc.acquire_grant_sync(
            scope=self.arc_scope,
            capabilities=self.arc_capabilities,
            budget=self.arc_budget,
        )

    def __del__(self):
        if hasattr(self, '_grant'):
            self._arc.release_grant_sync(self._grant)

    @staticmethod
    def requires(scope: str):
        """Decorator for actor methods requiring specific capability scope."""
        def decorator(method):
            @functools.wraps(method)
            def wrapper(self, *args, **kwargs):
                verdict = self._arc.evaluate_sync(
                    tool=method.__name__,
                    scope=scope,
                    grant_token=self._grant.token,
                )
                if verdict.denied:
                    raise PermissionError(f"ARC denied: {verdict.reason}")
                result = method(self, *args, **kwargs)
                self._arc.record_sync(verdict=verdict)
                return result
            return wrapper
        return decorator
```

### 3.3 Agent Swarm Pattern

Multiple agent actors coordinated by a supervisor, each with scoped
capabilities:

```python
@ray.remote
class SwarmSupervisor(ArcActor):
    arc_scope = "agent:supervisor"
    arc_capabilities = ["agent:delegate", "agent:observe"]

    def __init__(self, num_agents: int):
        super().__init__()
        # Spawn worker agents with delegated capabilities
        self.researchers = [
            ResearchAgent.remote() for _ in range(num_agents // 2)
        ]
        self.writers = [
            WriterAgent.remote() for _ in range(num_agents // 2)
        ]

    @ArcActor.requires("agent:delegate")
    async def dispatch(self, task: dict) -> dict:
        """Delegate to appropriate worker based on task type."""
        if task["type"] == "research":
            agent = self.researchers[hash(task["id"]) % len(self.researchers)]
            return await agent.search.remote(task["query"])
        elif task["type"] == "write":
            agent = self.writers[hash(task["id"]) % len(self.writers)]
            return await agent.write.remote(task["content"])

    @ArcActor.requires("agent:observe")
    def get_receipts(self) -> list[str]:
        """Collect receipt IDs from all agents in the swarm."""
        all_receipts = []
        for agent in self.researchers + self.writers:
            receipts = ray.get(agent.get_receipt_ids.remote())
            all_receipts.extend(receipts)
        return all_receipts
```

### 3.4 Ray Serve Integration

Ray Serve deployments as ARC-governed tool servers:

```python
from ray import serve
from arc_ray import ArcServeMiddleware

@serve.deployment
@serve.ingress(ArcServeMiddleware(scope="tools:inference"))
class InferenceServer:
    def __init__(self):
        self.model = load_model()

    async def predict(self, request) -> dict:
        # ArcServeMiddleware already evaluated the request
        # This only executes if ARC allowed it
        data = await request.json()
        return {"prediction": self.model.predict(data["input"])}
```

## 4. Receipt Aggregation

Ray tasks scatter across nodes. Receipts must aggregate:

```
Worker Node 1: receipt_a, receipt_b
Worker Node 2: receipt_c, receipt_d
                    |
                    v
ARC Receipt Aggregator (head node sidecar or dedicated actor)
                    |
                    v
WorkflowReceipt (Merkle tree of all step receipts)
```

```python
@ray.remote
class ReceiptAggregator:
    """Collects receipts from distributed tasks into a workflow receipt."""

    def __init__(self):
        self.arc = ArcClient()
        self.receipt_ids = []

    def add(self, receipt_id: str):
        self.receipt_ids.append(receipt_id)

    def finalize(self, workflow_id: str) -> str:
        return self.arc.finalize_workflow_sync(
            step_receipt_ids=self.receipt_ids,
            workflow_id=workflow_id,
        ).receipt_id
```

## 5. Placement Groups as Trust Zones

Ray placement groups co-locate actors on the same node(s). ARC can treat
a placement group as a trust boundary:

```python
from ray.util.placement_group import placement_group

# Create a trust zone -- all actors in this group share a policy domain
trusted_zone = placement_group(
    bundles=[{"CPU": 2, "GPU": 1}] * 4,
    strategy="STRICT_PACK",  # all on same node
)

# Actors in this placement group get elevated trust
@ray.remote(placement_group=trusted_zone)
class TrustedAgent(ArcActor):
    arc_scope = "agent:trusted-zone"
    arc_capabilities = ["tools:*"]  # broader access within trust zone
```

## 6. Package Structure

```
sdks/python/arc-ray/
  pyproject.toml            # deps: arc-sdk-python, ray[default]>=2.9
  src/arc_ray/
    __init__.py
    remote.py               # arc_remote decorator
    actor.py                # ArcActor base class
    serve.py                # ArcServeMiddleware
    aggregator.py           # ReceiptAggregator
    kernel_actor.py         # ArcKernelActor (ARC-as-actor mode)
  tests/
    test_remote.py
    test_actor.py
    test_swarm.py
    test_serve.py
```

## 7. Open Questions

1. **Object store governance.** Ray's object store holds intermediate
   results. Should ARC govern `ray.put()` / `ray.get()` for sensitive
   data objects?

2. **Autoscaling.** Ray autoscales workers. New nodes need ARC sidecars.
   Should the ARC sidecar be baked into the Ray node image, or deployed
   as a DaemonSet in K8s-on-Ray?

3. **Fault tolerance.** If a Ray actor dies and restarts, its standing
   capability grant is lost. Should grants persist in the ARC kernel and
   be re-acquired by the restarted actor?

4. **Multi-tenancy.** Ray clusters often serve multiple teams. Should ARC
   policy be per-namespace (Ray namespace), per-job, or per-actor?

5. **Chiodome alignment.** In the chiodome vision, agent swarms congregate
   as digital fiscal entities. How does ARC's per-actor capability model
   map to nation-state-level fiscal sovereignty? Is the placement group
   the "nation" boundary?
