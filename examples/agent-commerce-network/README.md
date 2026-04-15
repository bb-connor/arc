# Agent Commerce Network

This example is a flagship, real-life ARC scenario.

It models one buyer, one provider, one reviewer, one priced service family,
and five runnable scenario scripts around a cross-org agent commerce workflow:

- governed quote request
- approval-gated purchase
- budget denial
- dispute and reversal
- federated evidence review

The example is intentionally **high fidelity but scope-tight**:

- one buyer: `Acme Platform Security`
- one provider: `Contoso Red Team`
- one reviewer: `Northwind Assurance`
- one priced service family: `security-review`

It is also intentionally honest:

- the current version includes a real first live slice:
  - a buyer FastAPI procurement service
  - a wrapped MCP provider review service
  - a lightweight reviewer bundle verifier
- the scenarios still stage artifact bundles and runbooks under `artifacts/`
- the files are aligned to ARC's real operator, partner, federation, and
  receipt semantics

## Why this example exists

ARC is strongest when the workflow includes:

- budgeted authorization
- manual approval for larger actions
- partner-visible evidence and settlement artifacts
- cross-org trust and reconciliation
- explicit authoritative versus degraded paths

A simple chatbot demo would hide most of that. This example is designed to
show what ARC looks like when it governs a real economic workflow.

## Story

`Acme Platform Security` needs a code and cloud security review for a release.
Its buyer-side procurement agent requests a quote from `Contoso Red Team`.
The provider returns a priced quote for the `security-review` family. Smaller
quotes can auto-proceed; larger ones require approval. Once approved, the
provider executes the review, emits fulfillment artifacts, and both sides
reconcile the resulting settlement. `Northwind Assurance` can later import the
evidence package and verify the receipt chain without relying on raw logs.

## Recommended implementation stack

This example is designed so the first runnable version can be built from
already-shipped ARC surfaces.

### Shared control plane

- `arc trust serve` as the authority, receipt, budget, and operator-report
  surface
- optional receipt dashboard for inspection

### Buyer

- a small HTTP procurement API protected by `arc api protect`
- OpenAPI spec with ARC route metadata like:
  - `x-arc-side-effects`
  - `x-arc-approval-required`
- policy file for buyer-side spend, approval, and route constraints

### Provider

- one `security-review` service family
- can start as:
  - a wrapped MCP tool server behind `arc mcp serve-http`, or
  - a native ARC service similar to `examples/hello-tool`
- manifest or catalog metadata should carry indicative pricing and scope

### Reviewer

- a lightweight verifier that consumes exported evidence bundles
- can be shell or Python at first
- should resolve:
  - receipts
  - checkpoints / inclusion proof
  - reconciliation outputs
  - federated evidence import lineage

## Scenario list

### 1. Happy path

- buyer requests quote
- provider returns quote within budget
- execution proceeds
- fulfillment is delivered
- settlement reconciliation succeeds

### 2. Approval required

- provider quote exceeds the auto-approve threshold
- buyer-side approval artifact is required
- once approval is present, execution proceeds

### 3. Budget deny

- requested scope exceeds current budget envelope
- ARC denies before execution
- deny receipts and operator-facing outputs explain why

### 4. Dispute and reversal

- provider completes partial work or misses the agreed scope
- buyer disputes the claim
- reconciliation records a partial payout or reversal

### 5. Federated review

- reviewer imports bounded evidence from the buyer/provider flow
- lineage and trust boundaries are preserved
- the imported bundle is reviewable without pretending local issuance

## Files

- [compose.yaml](./compose.yaml): developer-oriented topology for the first live slice
- [docs/architecture.md](./docs/architecture.md): component model and request flow
- [docs/trust-boundaries.md](./docs/trust-boundaries.md): who trusts whom, and where ARC is authoritative
- [docs/receipt-chain.md](./docs/receipt-chain.md): expected evidence lineage across the workflow
- [buyer/openapi.yaml](./buyer/openapi.yaml): buyer-side procurement API shape
- [buyer/app.py](./buyer/app.py): live buyer procurement API
- [buyer/run-sidecar.sh](./buyer/run-sidecar.sh): wraps the buyer with `arc api protect`
- [buyer/policy.yaml](./buyer/policy.yaml): buyer-side capability and budget policy
- [provider/mock_review_mcp_server.py](./provider/mock_review_mcp_server.py): live provider MCP tool server
- [provider/run-edge.sh](./provider/run-edge.sh): wraps the provider with `arc mcp serve-http`
- [provider/review-family/security-review-family.yaml](./provider/review-family/security-review-family.yaml): provider offer family
- [reviewer/verify_bundle.py](./reviewer/verify_bundle.py): lightweight evidence verifier
- [contracts](./contracts): example quote, approval, fulfillment, settlement, and federated review artifacts
- [scenario](./scenario): executable scenario staging scripts

## How to use the scaffold now

Each scenario script stages a timestamped artifact bundle under
`artifacts/<scenario>/...` with:

- the scenario description
- copied contract examples
- a scenario-specific checklist
- expected ARC outputs

Run them from this directory:

```bash
./scenario/01-happy-path.sh
./scenario/02-approval-required.sh
./scenario/03-budget-deny.sh
./scenario/04-dispute-and-reversal.sh
./scenario/05-federated-review.sh
```

## First live slice

The example now ships a small but real local topology:

- `buyer/app.py`: FastAPI procurement service with in-memory state and a live provider client
- `buyer/run-sidecar.sh`: wraps the buyer API with `arc api protect`
- `provider/mock_review_mcp_server.py`: provider MCP tool server for the `security-review` family
- `provider/run-edge.sh`: wraps the provider with `arc mcp serve-http`
- `reviewer/verify_bundle.py`: validates staged or exported evidence bundles

### 1. Start trust control

```bash
mkdir -p examples/agent-commerce-network/artifacts/live/trust

cargo run --bin arc -- trust serve \
  --listen 127.0.0.1:8940 \
  --service-token demo-token \
  --receipt-db examples/agent-commerce-network/artifacts/live/trust/receipts.sqlite3 \
  --revocation-db examples/agent-commerce-network/artifacts/live/trust/revocations.sqlite3 \
  --authority-db examples/agent-commerce-network/artifacts/live/trust/authority.sqlite3 \
  --budget-db examples/agent-commerce-network/artifacts/live/trust/budgets.sqlite3
```

### 2. Start the provider edge

```bash
export ARC_CONTROL_URL=http://127.0.0.1:8940
export ARC_CONTROL_TOKEN=demo-token
export ARC_EDGE_TOKEN=demo-token

examples/agent-commerce-network/provider/run-edge.sh
```

### 3. Start the buyer API

```bash
cd examples/agent-commerce-network/buyer

export BUYER_PROVIDER_BASE_URL=http://127.0.0.1:8931
export BUYER_PROVIDER_AUTH_TOKEN=demo-token

uv run --project . uvicorn app:app --host 127.0.0.1 --port 8101
```

### 4. Put `arc api protect` in front of the buyer

```bash
export ARC_CONTROL_URL=http://127.0.0.1:8940
export ARC_CONTROL_TOKEN=demo-token
export BUYER_UPSTREAM_URL=http://127.0.0.1:8101

examples/agent-commerce-network/buyer/run-sidecar.sh
```

### 5. Drive the happy path

```bash
curl -s \
  -H 'content-type: application/json' \
  http://127.0.0.1:9101/procurement/quote-requests \
  -d '{
    "service_family": "security-review",
    "target": "git://acme.example/payments-api",
    "requested_scope": "release-review",
    "release_window": "2026-05-01T16:00:00Z"
  }' | jq
```

Use the returned `quote.quote_id` in:

```bash
curl -s \
  -H 'content-type: application/json' \
  http://127.0.0.1:9101/procurement/jobs \
  -d '{
    "quote_id": "<quote-id>",
    "provider_id": "contoso-red-team",
    "service_family": "security-review",
    "budget_minor": 150000
  }' | jq
```

If the quote is pending approval, approve it:

```bash
curl -s \
  -H 'content-type: application/json' \
  http://127.0.0.1:9101/procurement/jobs/<job-id>/approve \
  -d '{
    "approver": "alice@acme.example",
    "reason": "release window requires external review"
  }' | jq
```

### 6. Verify an evidence bundle

```bash
examples/agent-commerce-network/reviewer/run-verify.sh \
  "$(ls -td examples/agent-commerce-network/artifacts/happy-path/* | head -1)"
```

This first live slice keeps the example close to what the repo already ships while making the buyer, provider, and reviewer roles tangible.
