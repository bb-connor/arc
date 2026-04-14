# ARC Metering

**Version:** 1.0
**Date:** 2026-04-14
**Status:** Normative

This specification defines the receipt metering and cost attribution system
for ARC runtimes. Implementations MUST support the cost dimensions, budget
enforcement semantics, billing export formats, and query interface described
herein.

---

## 1. Purpose

ARC metering provides per-receipt cost attribution, cumulative budget
enforcement, billing-compatible export, and operator query tools. Every tool
invocation can carry cost metadata describing the resources consumed:
compute time, data volume, monetary API cost, and custom dimensions.

---

## 2. Cost Dimensions

Each receipt MAY carry zero or more cost dimensions. The following dimension
types are defined:

### 2.1 CostDimension

| Variant | Fields | Description |
|---------|--------|-------------|
| `ComputeTime` | `duration_ms: u64` | Wall-clock compute time in milliseconds |
| `DataVolume` | `bytes_read: u64, bytes_written: u64` | Data volume transferred in bytes |
| `ApiCost` | `amount: MonetaryAmount, provider: string` | Monetary cost charged by an upstream API |
| `Custom` | `name: string, value: u64, unit: string?` | Extensibility dimension with a numeric value |

`MonetaryAmount` is defined as:

| Field | Type | Description |
|-------|------|-------------|
| `units` | u64 | Cost in minor currency units (e.g., cents for USD) |
| `currency` | string | ISO 4217 currency code (e.g., `"USD"`, `"EUR"`) |

The `Custom` variant allows operators to track domain-specific metrics
(e.g., token counts, request counts) without modifying the protocol.

### 2.2 CostMetadata

Per-receipt cost metadata. Serialized as JSON and stored in the receipt's
metadata field under the `"cost"` key.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `schema` | string | Yes | MUST be `"arc.cost-metadata.v1"` |
| `receipt_id` | string | Yes | Receipt ID this cost belongs to |
| `timestamp` | u64 | Yes | Unix timestamp (seconds) of the receipt |
| `session_id` | string | No | Session that produced this receipt |
| `agent_id` | string | Yes | Agent that made the invocation |
| `tool_server` | string | Yes | Tool server that handled the invocation |
| `tool_name` | string | Yes | Tool that was invoked |
| `dimensions` | CostDimension[] | Yes | Individual cost measurements |
| `total_monetary_cost` | MonetaryAmount | No | Aggregate monetary cost across ApiCost dimensions |

### 2.3 Total Monetary Cost Computation

The `total_monetary_cost` field is computed by summing all `ApiCost`
dimension amounts. Implementations MUST use saturating addition to prevent
overflow.

When multiple `ApiCost` dimensions use different currencies, only amounts in
the first currency encountered are summed. Cross-currency amounts require
oracle conversion and are excluded from the automatic total. Implementations
SHOULD document this behavior to operators.

When no `ApiCost` dimensions are present, `total_monetary_cost` MUST be
`null`.

---

## 3. Budget Enforcement

Budget enforcement tracks cumulative spending and rejects invocations that
would exceed configured limits. Enforcement is fail-closed: any error during
budget evaluation MUST deny the request.

### 3.1 BudgetPolicy

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `max_total` | MonetaryAmount | Yes | Maximum total spending across all dimensions |
| `max_per_session` | MonetaryAmount | No | Per-session spending limit |
| `max_per_agent` | MonetaryAmount | No | Per-agent spending limit |
| `max_per_tool` | map[string, MonetaryAmount] | No | Per-tool limits; key format `"server:tool"` |
| `currency` | string | Yes | Currency for budget enforcement |

### 3.2 Enforcement Semantics

Budget checks evaluate in the following order. The first violation
encountered MUST be returned:

1. **Total budget**: `total_spent + cost > max_total.units`
2. **Per-session budget**: `session_spent + cost > max_per_session.units`
3. **Per-agent budget**: `agent_spent + cost > max_per_agent.units`
4. **Per-tool budget**: `tool_spent + cost > max_per_tool[key].units`

All arithmetic MUST use saturating addition. Overflow MUST saturate to
`u64::MAX` rather than wrapping.

A cost of zero MUST always pass budget checks regardless of current spending
levels.

### 3.3 BudgetViolation

When a budget check fails, the enforcer MUST return a typed violation:

| Variant | Fields | Description |
|---------|--------|-------------|
| `Total` | `limit_units, current_units, requested_units, currency` | Total budget exceeded |
| `Session` | `session_id, limit_units, current_units, requested_units, currency` | Per-session budget exceeded |
| `Agent` | `agent_id, limit_units, current_units, requested_units, currency` | Per-agent budget exceeded |
| `Tool` | `tool_key, limit_units, current_units, requested_units, currency` | Per-tool budget exceeded |

### 3.4 Recording

After a tool invocation succeeds and the receipt is signed, the enforcer
records the cost against all applicable counters (total, session, agent,
tool). Recording uses saturating addition.

The `record` operation does not enforce limits; it only updates tracking
counters. Budget enforcement happens exclusively in the `check` operation
before invocation.

---

## 4. Billing Export

Billing export transforms ARC cost metadata into flat, denormalized records
suitable for ingestion by external billing systems.

### 4.1 BillingRecord

| Field | Type | Description |
|-------|------|-------------|
| `schema` | string | MUST be `"arc.billing-export.v1"` |
| `receipt_id` | string | Receipt ID |
| `timestamp` | u64 | Unix timestamp (seconds) |
| `timestamp_iso` | string | ISO 8601 timestamp in UTC (e.g., `"2023-11-14T22:13:20Z"`) |
| `session_id` | string | Session ID (nullable) |
| `agent_id` | string | Agent that triggered the cost |
| `tool_server` | string | Tool server |
| `tool_name` | string | Tool name |
| `compute_time_ms` | u64 | Total compute time in milliseconds |
| `data_bytes` | u64 | Total data transferred in bytes |
| `cost_units` | u64 | Monetary cost in minor units (nullable) |
| `currency` | string | ISO 4217 currency code (nullable) |
| `provider` | string | Upstream provider (nullable) |

All timestamps MUST use ISO 8601 format with UTC timezone and `Z` suffix.
Implementations MUST fall back to `"unix:<timestamp>"` when the Unix
timestamp cannot be converted to a calendar date.

### 4.2 BillingExport

A batch of billing records.

| Field | Type | Description |
|-------|------|-------------|
| `schema` | string | MUST be `"arc.billing-export.v1"` |
| `exported_at` | u64 | Unix timestamp when the export was created |
| `record_count` | u64 | Total number of records in this export |
| `total_cost` | MonetaryAmount | Aggregate cost (null if mixed currencies) |
| `records` | BillingRecord[] | The billing records |

When records contain costs in multiple currencies, `total_cost` MUST be
`null` rather than summing incompatible amounts.

### 4.3 Export Formats

Implementations MUST support JSON export. Implementations SHOULD support
CSV export. CSV output MUST use the same field names as the JSON schema with
one record per row and a header line.

---

## 5. Query Interface

The query interface supports cost aggregation across multiple dimensions.

### 5.1 CostQuery

All filter fields are optional. When omitted, the filter matches all
records. Multiple filters are ANDed together.

| Field | Type | Description |
|-------|------|-------------|
| `session_id` | string | Filter by session ID |
| `agent_id` | string | Filter by agent ID |
| `tool_server` | string | Filter by tool server |
| `tool_name` | string | Filter by tool name |
| `since` | u64 | Start of time range, inclusive (Unix seconds) |
| `until` | u64 | End of time range, exclusive (Unix seconds) |
| `currency` | string | Only include costs in this currency |
| `limit` | usize | Maximum detailed records to return |
| `group_by` | GroupBy | Aggregation dimension |

### 5.2 GroupBy

| Value | Description |
|-------|-------------|
| `none` | No grouping; return individual receipt costs |
| `session` | Group by session ID |
| `agent` | Group by agent ID |
| `tool` | Group by tool key (`"server:tool_name"`) |

### 5.3 CostQueryResult

| Field | Type | Description |
|-------|------|-------------|
| `summary` | CostSummary | Aggregate statistics across all matching records |
| `groups` | CostGroup[] | Grouped rows (empty when group_by is `none`) |
| `truncated` | bool | Whether the result was truncated due to limit |

### 5.4 CostSummary

| Field | Type | Description |
|-------|------|-------------|
| `receipt_count` | u64 | Total matching receipts |
| `total_compute_time_ms` | u64 | Aggregate compute time |
| `total_data_bytes` | u64 | Aggregate data volume |
| `total_monetary_cost` | MonetaryAmount | Aggregate cost (null if mixed currencies) |
| `distinct_agents` | u64 | Number of distinct agents |
| `distinct_tools` | u64 | Number of distinct tools |

### 5.5 CostGroup

| Field | Type | Description |
|-------|------|-------------|
| `key` | string | Group key (session ID, agent ID, or `"server:tool"`) |
| `receipt_count` | u64 | Receipts in this group |
| `total_compute_time_ms` | u64 | Compute time for this group |
| `total_data_bytes` | u64 | Data volume for this group |
| `total_monetary_cost` | MonetaryAmount | Cost for this group (null if mixed currencies) |

### 5.6 Limits

The maximum number of records returned by a single query MUST NOT exceed
500. When the matching set exceeds the limit, the result MUST set
`truncated` to `true` and return only the first `limit` records. The
operator-provided `limit` is capped at the system maximum of 500.
