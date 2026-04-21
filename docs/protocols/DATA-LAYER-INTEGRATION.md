# Data Layer Integration: Governing Agent Access to Databases

> **Status**: Proposed April 2026
> **Priority**: P1 -- agents increasingly query databases directly via
> text-to-SQL, RAG retrieval, and analytical pipelines. Database access is
> the highest-risk data surface because a single unscoped query can
> exfiltrate a table, mutate production data, or run a warehouse query
> costing thousands of dollars.

## 1. The Problem

Every agent framework ships a database tool. LangChain has
`SQLDatabaseToolkit`. LlamaIndex has `NLSQLTableQueryEngine`. Custom agents
call Postgres, BigQuery, Pinecone, and Redis through tool wrappers. Today,
Chio governs the tool call itself ("can this agent invoke the `query` tool?")
but has no primitives for governing what the query does inside the database.

The gap:

```
Agent -> [Chio: can agent invoke "sql_query" tool?] -> tool server -> database
                                                          ^
                                            Chio says "allowed"
                                            but the query is:
                                            SELECT * FROM users;
                                            (exfiltrates entire table)
```

Chio needs to govern not just WHICH tools an agent calls, but WHAT those
tools do when the target is a data store. This means data-aware constraints
on `ToolGrant`, data-aware `ToolAction` variants for guards, and
data-aware `CostDimension` tracking for warehouse cost governance.

### The Risk Taxonomy

| Data store | Agent access pattern | What goes wrong |
|------------|---------------------|-----------------|
| SQL (Postgres, MySQL) | Text-to-SQL, direct query | Table exfiltration, destructive writes (DROP, DELETE without WHERE), SQL injection from LLM-generated queries |
| Vector DB (Pinecone, Qdrant, Weaviate) | RAG retrieval, similarity search | Cross-namespace data leakage, embedding exfiltration (reconstruction attacks), index poisoning via upsert |
| Data warehouse (BigQuery, Snowflake) | Analytical queries | Cost explosion ($10k query from a bad JOIN), cross-dataset access, PII in analytical results |
| NoSQL (MongoDB, DynamoDB) | CRUD operations | Collection-level exfiltration, unbounded scans, write amplification |
| Graph DB (Neo4j, Neptune) | Traversal queries | Unbounded traversals returning massive subgraphs, sensitive relationship exposure |
| Search (Elasticsearch, OpenSearch) | Full-text search | Index cross-access, result volume explosion |
| Cache (Redis, Memcached) | Key-value access | Session hijacking via key-pattern overreach, cache poisoning |

## 2. Architecture: Where Chio Intercepts

Chio intercepts at the kernel boundary -- between the agent and the tool
server -- never inside the tool server or at the database driver level.
The tool server wrapping the database submits query details as tool call
arguments, and Chio's guard pipeline evaluates them before execution.

```
Agent
  |
  | ToolCallRequest {
  |   tool_name: "sql_query",
  |   arguments: {
  |     "query": "SELECT name, email FROM users WHERE region = 'us-east'",
  |     "database": "analytics",
  |   },
  | }
  |
  v
Chio Kernel
  |
  +-- 1. ToolGrant check: does capability grant "sql_query" on this server?
  +-- 2. Constraint check: is "users" in TableAllowlist? Is operation ReadOnly?
  +-- 3. Guard pipeline: SqlQueryGuard parses query, checks tables, operations
  +-- 4. Budget check: estimated cost within max_cost_per_invocation?
  |
  | verdict: allow (or deny with reason)
  |
  v
Tool Server (database wrapper)
  |
  | executes query against database
  |
  v
Chio Kernel (post-invocation)
  |
  +-- 5. Result guard: row count within MaxRowsReturned?
  +-- 6. PII guard: sensitive columns redacted?
  +-- 7. Receipt: signed, includes CostDimension::DataVolume
  |
  v
Agent (receives governed result)
```

### Why Not Intercept at the Driver Level?

Chio treats tool servers as untrusted. The tool server is inside the sandbox;
the kernel is the trusted mediator. If Chio intercepted at the driver level
(inside the tool server process), a compromised tool server could bypass it.
The kernel boundary is the enforcement point. Tool servers submit queries as
tool arguments; guards parse and validate them.

## 3. Extending Chio's Type System

### 3.1 New Constraint Variants

The existing `Constraint` enum in `chio-core-types/src/capability.rs`
currently has `PathPrefix`, `DomainExact`, `DomainGlob`, `RegexMatch`,
`MaxLength`, `GovernedIntentRequired`, `RequireApprovalAbove`,
`SellerExact`, `MinimumRuntimeAssurance`, `MinimumAutonomyTier`, and
`Custom(String, String)`.

Proposed data layer additions:

```rust
pub enum Constraint {
    // ... existing variants ...

    // ---- Data Layer Constraints ----

    /// Restrict which database tables/collections the tool can access.
    /// The tool server must declare accessed tables in the tool arguments.
    /// Supports exact names and glob patterns (e.g., "analytics_*").
    TableAllowlist(Vec<String>),

    /// Restrict which vector database collections or namespaces are accessible.
    /// Format: "namespace/collection" or "namespace/*" for namespace-wide.
    CollectionAllowlist(Vec<String>),

    /// Restrict the class of database operations permitted.
    /// Guards use this to reject queries that exceed the granted operation class.
    OperationClass(DataOperationClass),

    /// Maximum number of rows the tool may return per invocation.
    /// The tool server must enforce this at query time (LIMIT clause)
    /// and Chio validates the result count post-invocation.
    MaxRowsReturned(u64),

    /// Maximum bytes scanned per query (for warehouse cost governance).
    /// Used with pre-execution dry-run cost estimation.
    MaxBytesScanned(u64),

    /// Maximum monetary cost per query, evaluated via warehouse dry-run.
    /// Uses the existing MonetaryAmount type for currency precision.
    MaxCostPerQuery(MonetaryAmount),

    /// Restrict which columns may appear in query results.
    /// Columns not in this list are either rejected pre-query (if the guard
    /// can parse the SELECT list) or redacted post-query by a result guard.
    ColumnAllowlist(Vec<String>),

    /// Columns that must never appear in results. Inverse of ColumnAllowlist.
    /// Used for PII governance: ["ssn", "credit_card", "date_of_birth"].
    ColumnDenylist(Vec<String>),

    /// Require a mandatory filter predicate on queries.
    /// Example: tenant isolation requires WHERE tenant_id = ?
    RequiredFilterPredicate {
        column: String,
        /// If set, the predicate value must equal this. If None, any value
        /// is accepted but the predicate must be present.
        expected_value: Option<String>,
    },

    /// Maximum traversal depth for graph database queries.
    MaxTraversalDepth(u32),

    /// Restrict Redis/cache key access to keys matching these patterns.
    /// Uses glob syntax: "session:agent-42:*", "cache:public:*".
    KeyPatternAllowlist(Vec<String>),
}

/// Classification of database operations by mutation level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataOperationClass {
    /// SELECT only. No mutations.
    ReadOnly,
    /// SELECT, INSERT. Can add data but not modify or delete.
    Append,
    /// SELECT, INSERT, UPDATE. Can modify but not delete or drop.
    ReadWrite,
    /// SELECT, INSERT, UPDATE, DELETE. Full CRUD but no schema changes.
    ReadWriteDelete,
    /// All operations including DDL (CREATE, ALTER, DROP).
    /// Almost never appropriate for agent access.
    Admin,
}
```

### 3.2 New ToolAction Variant

The `ToolAction` enum in `chio-guards/src/action.rs` needs a
`DatabaseQuery` variant so guards can pattern-match on database operations:

```rust
pub enum ToolAction {
    // ... existing variants ...

    /// Database query execution.
    DatabaseQuery {
        /// The database engine or type.
        engine: DatabaseEngine,
        /// The raw query text (SQL, Cypher, MQL, etc.).
        query: String,
        /// Parsed operation class (derived from query analysis).
        operation_class: DataOperationClass,
        /// Tables/collections referenced in the query.
        tables: Vec<String>,
        /// Columns in the SELECT projection (if parseable).
        columns: Vec<String>,
        /// Whether the query has a LIMIT clause.
        has_limit: bool,
        /// Whether the query has a WHERE clause.
        has_filter: bool,
        /// Estimated cost from warehouse dry-run, if available.
        estimated_cost: Option<MonetaryAmount>,
        /// Estimated bytes to scan, if available.
        estimated_bytes: Option<u64>,
        /// Target database/schema/namespace identifier.
        target: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DatabaseEngine {
    Postgres,
    Mysql,
    Sqlite,
    BigQuery,
    Snowflake,
    Redshift,
    Databricks,
    MongoDB,
    DynamoDB,
    Firestore,
    Neo4j,
    Neptune,
    Elasticsearch,
    OpenSearch,
    Redis,
    Pinecone,
    Qdrant,
    Weaviate,
    Chroma,
    Milvus,
    Pgvector,
    Other(String),
}
```

### 3.3 New CostDimension Variant

The existing `CostDimension` enum in `chio-metering` already has
`DataVolume { bytes_read, bytes_written }` and `ApiCost`. Add a
warehouse-specific variant:

```rust
pub enum CostDimension {
    // ... existing variants ...

    /// Data warehouse query cost with scan metadata.
    WarehouseQuery {
        /// Monetary cost of the query (from warehouse billing API).
        cost: MonetaryAmount,
        /// Bytes scanned by the query engine.
        bytes_scanned: u64,
        /// Rows returned to the caller.
        rows_returned: u64,
        /// Query execution time in milliseconds.
        execution_ms: u64,
        /// Warehouse provider (bigquery, snowflake, etc.).
        provider: String,
        /// Slot time or compute units consumed (warehouse-specific).
        compute_units: Option<u64>,
    },
}
```

### 3.4 ResourceGrant URI Patterns for Data

The existing `ResourceGrant.uri_pattern` with glob matching can express
data layer scoping without new types:

```
SQL:
  "sql://analytics-db/public/users"        -- specific table
  "sql://analytics-db/public/*"            -- all tables in schema
  "sql://analytics-db/*"                   -- all schemas
  "sql://*/public/users"                   -- users table on any server

Vector:
  "vector://pinecone/prod-ns/embeddings"   -- specific collection
  "vector://pinecone/prod-ns/*"            -- all collections in namespace
  "vector://qdrant/*/customer-*"           -- customer collections on any ns

Warehouse:
  "warehouse://bigquery/my-project/analytics/*"    -- all tables in dataset
  "warehouse://snowflake/my-db/public/sales"       -- specific table

NoSQL:
  "nosql://mongodb/mydb/users"             -- specific collection
  "nosql://dynamodb/*/sessions"            -- sessions table on any region

Graph:
  "graph://neo4j/knowledge-graph"          -- specific graph database

Search:
  "search://elasticsearch/products-*"      -- indices matching pattern

Cache:
  "cache://redis/session:agent-42:*"       -- key pattern
```

This means data layer scoping can work today via `ResourceGrant` without
any type changes. The new `Constraint` variants add defense in depth on
top of URI-based scoping.

## 4. Guard Implementations

### 4.1 SQL Query Guard

Parses SQL queries and enforces constraints:

```rust
/// Guard that analyzes SQL queries against data layer constraints.
pub struct SqlQueryGuard {
    /// SQL parser (supports Postgres, MySQL, BigQuery, Snowflake dialects).
    parser: SqlParser,
}

impl Guard for SqlQueryGuard {
    fn evaluate(&self, context: &GuardContext) -> GuardVerdict {
        // Extract query from tool call arguments
        let query = match context.request.arguments.get("query") {
            Some(Value::String(q)) => q,
            _ => return GuardVerdict::Allow, // Not a query tool call
        };

        // Parse the SQL
        let parsed = match self.parser.parse(query) {
            Ok(p) => p,
            Err(_) => return GuardVerdict::Deny {
                reason: "Failed to parse SQL query -- unparseable queries are denied".into(),
            },
        };

        // Check operation class
        if let Some(Constraint::OperationClass(max_class)) = find_constraint(context, "operation_class") {
            if parsed.operation_class > max_class {
                return GuardVerdict::Deny {
                    reason: format!(
                        "Query is {:?} but grant only permits {:?}",
                        parsed.operation_class, max_class,
                    ),
                };
            }
        }

        // Check table allowlist
        if let Some(Constraint::TableAllowlist(allowed)) = find_constraint(context, "table_allowlist") {
            for table in &parsed.tables {
                if !matches_any_pattern(table, &allowed) {
                    return GuardVerdict::Deny {
                        reason: format!(
                            "Query accesses table '{}' which is not in the allowlist: {:?}",
                            table, allowed,
                        ),
                    };
                }
            }
        }

        // Check column denylist (PII columns)
        if let Some(Constraint::ColumnDenylist(denied)) = find_constraint(context, "column_denylist") {
            for col in &parsed.select_columns {
                if denied.contains(col) {
                    return GuardVerdict::Deny {
                        reason: format!(
                            "Query selects denied column '{}' (PII-protected)",
                            col,
                        ),
                    };
                }
            }
            // Also check SELECT * -- must be denied if any column is restricted
            if parsed.is_select_star {
                return GuardVerdict::Deny {
                    reason: "SELECT * is denied when column restrictions are active".into(),
                };
            }
        }

        // Check required filter predicate (tenant isolation)
        if let Some(Constraint::RequiredFilterPredicate { column, expected_value }) =
            find_constraint(context, "required_filter_predicate")
        {
            if !parsed.has_predicate_on(&column, expected_value.as_deref()) {
                return GuardVerdict::Deny {
                    reason: format!(
                        "Query must include a WHERE predicate on column '{}'",
                        column,
                    ),
                };
            }
        }

        // Check LIMIT clause
        if let Some(Constraint::MaxRowsReturned(max)) = find_constraint(context, "max_rows") {
            match parsed.limit {
                None => return GuardVerdict::Deny {
                    reason: format!(
                        "Query has no LIMIT clause; grant requires at most {} rows",
                        max,
                    ),
                },
                Some(limit) if limit > max => return GuardVerdict::Deny {
                    reason: format!(
                        "Query LIMIT {} exceeds grant maximum of {} rows",
                        limit, max,
                    ),
                },
                _ => {}
            }
        }

        // Specific dangerous pattern detection
        if parsed.is_destructive_without_where() {
            return GuardVerdict::Deny {
                reason: "DELETE/UPDATE without WHERE clause is always denied".into(),
            };
        }

        if parsed.contains_ddl() {
            if !matches!(
                find_constraint(context, "operation_class"),
                Some(Constraint::OperationClass(DataOperationClass::Admin))
            ) {
                return GuardVerdict::Deny {
                    reason: "DDL operations (CREATE/ALTER/DROP) require Admin operation class".into(),
                };
            }
        }

        GuardVerdict::Allow
    }
}
```

### 4.2 Warehouse Cost Guard

Pre-execution cost estimation using warehouse dry-run APIs:

```rust
/// Guard that estimates warehouse query cost before execution.
pub struct WarehouseCostGuard {
    /// Client for warehouse dry-run APIs.
    estimator: CostEstimator,
}

impl Guard for WarehouseCostGuard {
    fn evaluate(&self, context: &GuardContext) -> GuardVerdict {
        let query = match context.request.arguments.get("query") {
            Some(Value::String(q)) => q,
            _ => return GuardVerdict::Allow,
        };

        let engine = context.request.arguments.get("engine")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        // Run dry-run to estimate cost
        let estimate = match self.estimator.estimate(engine, query) {
            Ok(e) => e,
            Err(_) => return GuardVerdict::Deny {
                reason: "Failed to estimate query cost -- unestimable queries are denied".into(),
            },
        };

        // Check bytes scanned
        if let Some(Constraint::MaxBytesScanned(max)) = find_constraint(context, "max_bytes") {
            if estimate.bytes_scanned > max {
                return GuardVerdict::Deny {
                    reason: format!(
                        "Query would scan {} bytes, exceeding limit of {} bytes ({} vs {})",
                        estimate.bytes_scanned, max,
                        human_bytes(estimate.bytes_scanned),
                        human_bytes(max),
                    ),
                };
            }
        }

        // Check monetary cost
        if let Some(Constraint::MaxCostPerQuery(max_cost)) = find_constraint(context, "max_cost_query") {
            if estimate.estimated_cost.units > max_cost.units {
                return GuardVerdict::Deny {
                    reason: format!(
                        "Query estimated cost ${:.2} exceeds limit ${:.2}",
                        estimate.estimated_cost.to_dollars(),
                        max_cost.to_dollars(),
                    ),
                };
            }
        }

        // Also check against the ToolGrant.max_cost_per_invocation
        // (this is handled by the kernel's budget check, but the guard
        // can provide a more helpful error message)

        GuardVerdict::Allow
    }
}
```

### 4.3 Vector Database Guard

```rust
/// Guard that enforces vector database access constraints.
pub struct VectorDbGuard;

impl Guard for VectorDbGuard {
    fn evaluate(&self, context: &GuardContext) -> GuardVerdict {
        let collection = context.request.arguments.get("collection")
            .and_then(|v| v.as_str());
        let namespace = context.request.arguments.get("namespace")
            .and_then(|v| v.as_str());
        let operation = context.request.arguments.get("operation")
            .and_then(|v| v.as_str())
            .unwrap_or("query");
        let top_k = context.request.arguments.get("top_k")
            .and_then(|v| v.as_u64());

        // Check collection allowlist
        if let (Some(collection), Some(Constraint::CollectionAllowlist(allowed))) =
            (collection, find_constraint(context, "collection_allowlist"))
        {
            let full_path = match namespace {
                Some(ns) => format!("{}/{}", ns, collection),
                None => collection.to_string(),
            };

            if !matches_any_pattern(&full_path, &allowed) {
                return GuardVerdict::Deny {
                    reason: format!(
                        "Collection '{}' is not in the allowlist: {:?}",
                        full_path, allowed,
                    ),
                };
            }
        }

        // Check operation class (query vs upsert vs delete)
        if let Some(Constraint::OperationClass(max_class)) = find_constraint(context, "operation_class") {
            let op_class = match operation {
                "query" | "search" | "fetch" => DataOperationClass::ReadOnly,
                "upsert" | "insert" => DataOperationClass::Append,
                "update" => DataOperationClass::ReadWrite,
                "delete" => DataOperationClass::ReadWriteDelete,
                "create_collection" | "delete_collection" => DataOperationClass::Admin,
                _ => DataOperationClass::ReadWrite, // conservative default
            };

            if op_class > max_class {
                return GuardVerdict::Deny {
                    reason: format!(
                        "Operation '{}' ({:?}) exceeds granted {:?}",
                        operation, op_class, max_class,
                    ),
                };
            }
        }

        // Check top_k limit
        if let (Some(k), Some(Constraint::MaxRowsReturned(max))) =
            (top_k, find_constraint(context, "max_rows"))
        {
            if k > max {
                return GuardVerdict::Deny {
                    reason: format!(
                        "top_k={} exceeds maximum of {} results",
                        k, max,
                    ),
                };
            }
        }

        GuardVerdict::Allow
    }
}
```

### 4.4 Post-Invocation Result Guard

Evaluates tool results AFTER execution, before returning to the agent:

```rust
/// Guard that inspects query results for constraint violations.
/// Runs post-invocation (after the tool server returns).
pub struct QueryResultGuard;

impl PostInvocationGuard for QueryResultGuard {
    fn evaluate_result(
        &self,
        context: &GuardContext,
        result: &ToolCallResponse,
    ) -> PostInvocationVerdict {
        // Check row count against MaxRowsReturned
        if let Some(Constraint::MaxRowsReturned(max)) = find_constraint(context, "max_rows") {
            if let Some(row_count) = result.metadata.get("row_count").and_then(|v| v.as_u64()) {
                if row_count > max {
                    return PostInvocationVerdict::Redact {
                        reason: format!(
                            "Result contains {} rows, exceeding limit of {}. Truncating.",
                            row_count, max,
                        ),
                        truncate_to: max as usize,
                    };
                }
            }
        }

        // Check for PII in result columns
        if let Some(Constraint::ColumnDenylist(denied)) = find_constraint(context, "column_denylist") {
            if let Some(columns) = result.metadata.get("columns").and_then(|v| v.as_array()) {
                let returned_columns: Vec<&str> = columns.iter()
                    .filter_map(|c| c.as_str())
                    .collect();

                let violations: Vec<&&str> = returned_columns.iter()
                    .filter(|c| denied.iter().any(|d| d == **c))
                    .collect();

                if !violations.is_empty() {
                    return PostInvocationVerdict::RedactColumns {
                        reason: format!(
                            "Result contains denied columns: {:?}",
                            violations,
                        ),
                        columns_to_redact: violations.into_iter().map(|s| s.to_string()).collect(),
                    };
                }
            }
        }

        PostInvocationVerdict::Allow
    }
}
```

## 5. Data Store Integration Patterns

### 5.1 SQL Databases (PostgreSQL, MySQL)

**Tool server contract**: The database tool server must submit structured
arguments that Chio guards can evaluate:

```json
{
  "tool_name": "sql_query",
  "arguments": {
    "query": "SELECT name, email FROM users WHERE tenant_id = 'acme' LIMIT 100",
    "database": "analytics",
    "engine": "postgres",
    "operation_hint": "read"
  }
}
```

**Capability grant**:

```json
{
  "server_id": "analytics-db",
  "tool_name": "sql_query",
  "operations": ["invoke"],
  "constraints": [
    { "type": "table_allowlist", "value": ["users", "orders", "products"] },
    { "type": "operation_class", "value": "read_only" },
    { "type": "column_denylist", "value": ["ssn", "credit_card_number", "password_hash"] },
    { "type": "required_filter_predicate", "value": { "column": "tenant_id" } },
    { "type": "max_rows_returned", "value": 1000 }
  ],
  "max_invocations": 500,
  "max_total_cost": { "units": 0, "currency": "USD" }
}
```

**What gets denied**:

```sql
-- Denied: table not in allowlist
SELECT * FROM salaries;

-- Denied: operation class violation (ReadOnly grant)
DELETE FROM users WHERE id = 42;

-- Denied: column denylist
SELECT name, ssn FROM users;

-- Denied: SELECT * with column restrictions active
SELECT * FROM users;

-- Denied: missing tenant isolation predicate
SELECT name FROM users WHERE region = 'us-east';

-- Denied: no LIMIT clause
SELECT name FROM users WHERE tenant_id = 'acme';

-- Denied: LIMIT exceeds maximum
SELECT name FROM users WHERE tenant_id = 'acme' LIMIT 50000;

-- Allowed:
SELECT name, email FROM users WHERE tenant_id = 'acme' LIMIT 100;
```

### 5.2 Vector Databases (Pinecone, Qdrant, Weaviate, Chroma)

**Tool server contract**:

```json
{
  "tool_name": "vector_search",
  "arguments": {
    "collection": "product-embeddings",
    "namespace": "production",
    "operation": "query",
    "query_vector": [0.1, 0.2, ...],
    "top_k": 10,
    "filter": { "category": "electronics" },
    "include_vectors": false
  }
}
```

**Capability grant**:

```json
{
  "server_id": "pinecone-prod",
  "tool_name": "vector_search",
  "operations": ["invoke"],
  "constraints": [
    { "type": "collection_allowlist", "value": ["production/product-embeddings", "production/faq-*"] },
    { "type": "operation_class", "value": "read_only" },
    { "type": "max_rows_returned", "value": 50 }
  ],
  "max_invocations": 1000
}
```

**What gets denied**:

```
-- Denied: collection not in allowlist
collection: "internal-hr-embeddings", namespace: "production"

-- Denied: cross-namespace access
collection: "product-embeddings", namespace: "staging"

-- Denied: write operation on read-only grant
operation: "upsert"

-- Denied: top_k exceeds maximum
top_k: 500

-- Allowed:
collection: "product-embeddings", namespace: "production", operation: "query", top_k: 10
```

**Embedding exfiltration protection**: The `include_vectors: false` field
should be enforced by a guard when the operation class is ReadOnly. Raw
vectors enable reconstruction attacks -- an agent should get document
content, not embedding vectors, unless explicitly granted.

### 5.3 Data Warehouses (BigQuery, Snowflake, Databricks)

Data warehouses are the most cost-sensitive integration. A single unscoped
query can scan terabytes and cost thousands of dollars.

**Tool server contract**:

```json
{
  "tool_name": "warehouse_query",
  "arguments": {
    "query": "SELECT user_id, SUM(amount) FROM orders GROUP BY user_id",
    "engine": "bigquery",
    "project": "my-project",
    "dataset": "analytics",
    "dry_run_estimate": {
      "bytes_scanned": 52428800,
      "estimated_cost": { "units": 25, "currency": "USD" }
    }
  }
}
```

The `dry_run_estimate` is critical. BigQuery and Snowflake both support
dry-run queries that return estimated bytes without executing. The tool
server runs the dry-run first and includes the estimate in the tool call
arguments. The `WarehouseCostGuard` evaluates the estimate before allowing
execution.

**Capability grant**:

```json
{
  "server_id": "bigquery-analytics",
  "tool_name": "warehouse_query",
  "operations": ["invoke"],
  "constraints": [
    { "type": "table_allowlist", "value": ["analytics.orders", "analytics.products"] },
    { "type": "operation_class", "value": "read_only" },
    { "type": "max_bytes_scanned", "value": 1073741824 },
    { "type": "max_cost_per_query", "value": { "units": 500, "currency": "USD" } },
    { "type": "column_denylist", "value": ["email", "phone", "address"] },
    { "type": "max_rows_returned", "value": 10000 }
  ],
  "max_cost_per_invocation": { "units": 500, "currency": "USD" },
  "max_total_cost": { "units": 5000, "currency": "USD" }
}
```

**Cost governance flow**:

```
Agent submits query
     |
     v
Tool server runs BigQuery dry-run
  -> "This query will scan 50 GB, estimated cost $0.25"
     |
     v
Tool server submits to Chio with dry_run_estimate
     |
     v
Chio WarehouseCostGuard:
  - 50 GB < MaxBytesScanned (1 GB)? NO -> DENY
  OR
  - 50 GB < MaxBytesScanned (100 GB)? YES
  - $0.25 < MaxCostPerQuery ($5.00)? YES -> ALLOW
     |
     v
Tool server executes actual query
     |
     v
Chio receipt records CostDimension::WarehouseQuery {
  cost: $0.25,
  bytes_scanned: 50 GB,
  rows_returned: 847,
  execution_ms: 3200,
  provider: "bigquery",
}
     |
     v
Budget tracker: $0.25 of $50.00 total budget consumed
```

### 5.4 NoSQL Databases (MongoDB, DynamoDB, Firestore)

**Tool server contract**:

```json
{
  "tool_name": "nosql_query",
  "arguments": {
    "engine": "mongodb",
    "database": "myapp",
    "collection": "users",
    "operation": "find",
    "filter": { "tenant_id": "acme", "active": true },
    "projection": { "name": 1, "email": 1 },
    "limit": 100
  }
}
```

**Capability grant**:

```json
{
  "server_id": "mongodb-prod",
  "tool_name": "nosql_query",
  "operations": ["invoke"],
  "constraints": [
    { "type": "collection_allowlist", "value": ["users", "orders", "products"] },
    { "type": "operation_class", "value": "read_only" },
    { "type": "required_filter_predicate", "value": { "column": "tenant_id" } },
    { "type": "max_rows_returned", "value": 500 }
  ]
}
```

**DynamoDB-specific**: DynamoDB has consumed capacity units (RCU/WCU) that
map directly to `CostDimension::Custom { name: "rcu", value: 50 }`. The
budget tracker can enforce per-session RCU limits.

### 5.5 Graph Databases (Neo4j, Neptune)

**Tool server contract**:

```json
{
  "tool_name": "graph_query",
  "arguments": {
    "engine": "neo4j",
    "query": "MATCH (p:Person)-[:KNOWS*1..3]->(friend) WHERE p.name = 'Alice' RETURN friend.name",
    "database": "knowledge-graph",
    "max_depth": 3,
    "node_labels": ["Person"],
    "relationship_types": ["KNOWS"]
  }
}
```

**Unique constraint**: `MaxTraversalDepth` prevents unbounded graph
traversals. A query like `MATCH (a)-[*]->(b)` (unlimited depth) on a
large graph can return millions of paths. The guard should also check
that the depth parameter in the query matches the constraint.

### 5.6 Search Engines (Elasticsearch, OpenSearch)

**Tool server contract**:

```json
{
  "tool_name": "search",
  "arguments": {
    "engine": "elasticsearch",
    "index": "products-v2",
    "query": { "match": { "description": "wireless headphones" } },
    "size": 20,
    "source_includes": ["name", "price", "description"]
  }
}
```

Search is lower risk than SQL (inherently read-only) but index-level
isolation matters. An agent searching `products` should not be able to
search `internal-documents`.

### 5.7 Cache / Session Stores (Redis)

**Tool server contract**:

```json
{
  "tool_name": "cache_access",
  "arguments": {
    "engine": "redis",
    "operation": "get",
    "key": "session:agent-42:state",
    "pattern": null
  }
}
```

**Unique constraint**: `KeyPatternAllowlist` scopes Redis access to
specific key prefixes. An agent with `session:agent-42:*` cannot read
`session:agent-99:*` (another agent's session data) or `admin:*`
(administrative keys).

**Dangerous operations**: `KEYS *`, `FLUSHDB`, `FLUSHALL`, `CONFIG SET`
should be denied by default unless the grant has `Admin` operation class.

## 6. PII Governance

### 6.1 Column-Level PII Protection

The `ColumnDenylist` constraint is the primary mechanism. Organizations
define which columns contain PII:

```yaml
# chio-policy.yaml
pii_columns:
  - ssn
  - social_security_number
  - credit_card_number
  - credit_card
  - date_of_birth
  - dob
  - password_hash
  - password
  - phone_number
  - phone
  - email_address
  - home_address
  - address
  - ip_address
```

The `SqlQueryGuard` checks SELECT columns against this list. The
`QueryResultGuard` provides defense-in-depth by inspecting returned column
names post-execution.

### 6.2 Result-Level PII Detection

A WASM guard can scan query results for PII patterns before returning
them to the agent:

```rust
/// WASM guard that scans query results for PII patterns.
pub struct PiiDetectionGuard {
    patterns: Vec<PiiPattern>,
}

struct PiiPattern {
    name: &'static str,
    regex: Regex,
}

// Patterns:
// SSN: \d{3}-\d{2}-\d{4}
// Credit card: \d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}
// Email: [a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}
// Phone: \+?\d{1,3}[\s-]?\(?\d{3}\)?[\s-]?\d{3}[\s-]?\d{4}
```

### 6.3 Data Residency

The `ResourceGrant.uri_pattern` can encode region constraints:

```
"sql://us-east-1.analytics-db/public/*"    -- only US East databases
"warehouse://bigquery/eu-project/eu-data/*" -- only EU BigQuery datasets
```

A guard validates that the tool server's declared region matches the
capability token's region constraint. This prevents an agent with EU data
access from querying a US-region database, even if the table name matches.

## 7. Tool Server Contract

For data layer governance to work, tool servers wrapping databases must
submit structured arguments that guards can evaluate. This is a contract
between the tool server and the Chio kernel.

### Required Argument Fields

| Field | Type | Required | Purpose |
|-------|------|----------|---------|
| `query` | string | Yes (SQL/Cypher) | The raw query text for parsing |
| `engine` | string | Yes | Database engine for dialect-aware parsing |
| `database` / `target` | string | Yes | Target database/schema/namespace |
| `operation` | string | Recommended | Operation type (query/insert/update/delete) |
| `tables` / `collection` | string[] / string | Recommended | Tables or collections accessed |
| `columns` | string[] | Optional | Columns in SELECT projection |
| `limit` | number | Optional | Row limit (guards can also parse from query) |
| `dry_run_estimate` | object | Required (warehouses) | Pre-execution cost estimate |

If the tool server does not provide structured arguments (e.g., only
submits a raw query string), the guard must parse the query. SQL parsing
is well-supported. For non-SQL databases, the tool server should provide
operation and target metadata.

### Manifest Declaration

Tool servers declare their database access pattern in the Chio manifest:

```json
{
  "tools": [
    {
      "name": "sql_query",
      "description": "Execute a SQL query against the analytics database",
      "input_schema": {
        "type": "object",
        "properties": {
          "query": { "type": "string", "description": "SQL query to execute" },
          "database": { "type": "string", "enum": ["analytics", "reporting"] },
          "engine": { "type": "string", "const": "postgres" }
        },
        "required": ["query"]
      },
      "annotations": {
        "arc:data_layer": "sql",
        "arc:engine": "postgres",
        "arc:default_operation_class": "read_only",
        "arc:supports_dry_run": false,
        "arc:tables": ["users", "orders", "products", "sessions"]
      }
    }
  ]
}
```

The `arc:*` annotations inform the kernel which guards to activate and
what constraints are meaningful for this tool.

## 8. Python SDK Integration

### 8.1 Database Tool Decorators

```python
from chio_sdk import ChioClient
from chio_data import chio_query, chio_vector_search, DataScope

# SQL query with Chio governance
@chio_query(
    scope=DataScope.sql(
        tables=["users", "orders"],
        operation_class="read_only",
        max_rows=1000,
        deny_columns=["ssn", "credit_card"],
        require_filter="tenant_id",
    ),
)
async def query_users(query: str, tenant_id: str) -> list[dict]:
    """Execute a governed SQL query."""
    return await db.fetch_all(query)


# Vector search with Chio governance
@chio_vector_search(
    scope=DataScope.vector(
        collections=["prod/product-embeddings", "prod/faq-*"],
        operation_class="read_only",
        max_results=50,
    ),
)
async def search_products(query_vector: list[float], top_k: int = 10) -> list[dict]:
    """Execute a governed vector similarity search."""
    return await pinecone_index.query(vector=query_vector, top_k=top_k)


# Warehouse query with cost governance
@chio_query(
    scope=DataScope.warehouse(
        engine="bigquery",
        tables=["analytics.orders", "analytics.products"],
        max_bytes_scanned=1_000_000_000,  # 1 GB
        max_cost_per_query_usd=5.00,
        max_total_cost_usd=50.00,
    ),
)
async def analytics_query(query: str) -> list[dict]:
    """Execute a governed BigQuery query with cost limits."""
    # Dry-run happens automatically in the decorator
    return await bq_client.query(query).result()
```

### 8.2 LangChain Integration

Wrap LangChain's database toolkits with Chio governance:

```python
from langchain_community.utilities import SQLDatabase
from langchain_community.agent_toolkits import SQLDatabaseToolkit
from chio_data.langchain import ChioSQLDatabaseToolkit

# Standard LangChain SQL toolkit
db = SQLDatabase.from_uri("postgresql://localhost/analytics")
toolkit = SQLDatabaseToolkit(db=db, llm=llm)

# Chio-governed wrapper
chio_toolkit = ChioSQLDatabaseToolkit(
    toolkit=toolkit,
    sidecar_url="http://127.0.0.1:9090",
    table_allowlist=["users", "orders", "products"],
    operation_class="read_only",
    column_denylist=["ssn", "credit_card_number"],
    max_rows=1000,
    require_tenant_filter="tenant_id",
)

# Use in agent -- same interface, Chio-governed
agent = create_sql_agent(llm=llm, toolkit=chio_toolkit)
result = agent.invoke("How many orders did we get last month?")
# Chio evaluates every generated SQL query before execution
```

### 8.3 LlamaIndex Integration

```python
from llama_index.core import SQLDatabase, VectorStoreIndex
from chio_data.llamaindex import ChioSQLDatabase, ChioVectorStoreIndex

# Chio-governed SQL database for text-to-SQL
chio_db = ChioSQLDatabase(
    sql_database=SQLDatabase.from_uri("postgresql://localhost/analytics"),
    table_allowlist=["users", "orders"],
    operation_class="read_only",
    max_rows=500,
)

# Chio-governed vector store for RAG
chio_index = ChioVectorStoreIndex(
    vector_store=pinecone_store,
    collection_allowlist=["prod/product-embeddings"],
    max_results=20,
)
```

## 9. Receipt Metadata for Data Operations

Every data layer operation produces a receipt with data-specific metadata:

```json
{
  "receipt_id": "rcpt_abc123",
  "tool_name": "sql_query",
  "server_id": "analytics-db",
  "verdict": "allow",
  "metadata": {
    "arc:data_layer": "sql",
    "arc:engine": "postgres",
    "arc:operation_class": "read_only",
    "arc:tables_accessed": ["users"],
    "arc:columns_returned": ["name", "email", "created_at"],
    "arc:rows_returned": 47,
    "arc:query_hash": "sha256:a1b2c3d4...",
    "arc:had_limit": true,
    "arc:had_tenant_filter": true,
    "arc:tenant_id": "acme"
  },
  "cost": {
    "dimensions": [
      {
        "dimension": "data_volume",
        "bytes_read": 94208,
        "bytes_written": 0
      }
    ]
  }
}
```

For warehouse queries, the receipt also includes:

```json
{
  "cost": {
    "dimensions": [
      {
        "dimension": "warehouse_query",
        "cost": { "units": 25, "currency": "USD" },
        "bytes_scanned": 52428800,
        "rows_returned": 847,
        "execution_ms": 3200,
        "provider": "bigquery"
      }
    ],
    "total_monetary_cost": { "units": 25, "currency": "USD" }
  }
}
```

## 10. Package Structure

```
crates/
  chio-data-guards/
    Cargo.toml                  # deps: chio-core-types, chio-guards, sqlparser
    src/
      lib.rs
      sql_guard.rs              # SqlQueryGuard
      vector_guard.rs           # VectorDbGuard
      warehouse_cost_guard.rs   # WarehouseCostGuard
      result_guard.rs           # QueryResultGuard (post-invocation)
      pii_guard.rs              # PiiDetectionGuard
      sql_parser.rs             # Dialect-aware SQL analysis
      action.rs                 # DatabaseQuery ToolAction variant
    tests/
      test_sql_guard.rs
      test_vector_guard.rs
      test_warehouse_cost.rs
      test_pii.rs

sdks/python/chio-data/
  pyproject.toml                # deps: chio-sdk-python, sqlparse
  src/chio_data/
    __init__.py
    scope.py                    # DataScope builder
    decorators.py               # chio_query, chio_vector_search
    langchain/
      __init__.py
      toolkit.py                # ChioSQLDatabaseToolkit
    llamaindex/
      __init__.py
      database.py               # ChioSQLDatabase
      vector_store.py           # ChioVectorStoreIndex
  tests/
    test_sql_scope.py
    test_vector_scope.py
    test_warehouse_cost.py
    test_langchain.py
    test_llamaindex.py
```

## 11. Open Questions

1. **SQL parsing fidelity.** SQL dialects vary (Postgres, MySQL, BigQuery
   SQL, Snowflake SQL, Spark SQL). The `sqlparser` crate supports multiple
   dialects but is not perfect. Should unparseable queries be denied
   (fail-closed) or delegated to the tool server with a warning?
   Recommendation: fail-closed, matching Chio's convention.

2. **Prepared statements.** If the tool server uses parameterized queries,
   the guard sees `SELECT * FROM users WHERE id = $1` without knowing the
   parameter value. Should the guard evaluate the template, the parameters
   separately, or require the tool server to submit the expanded query?

3. **Stored procedures.** `CALL my_procedure()` hides the actual operations
   inside the database. The guard cannot inspect what the procedure does.
   Should stored procedure calls require `Admin` operation class, or should
   the tool server declare what operations the procedure performs in the
   manifest?

4. **ORMs and query builders.** If the tool server uses SQLAlchemy or
   Prisma, it generates SQL that the guard can parse. But the ORM's
   relationship loading (eager/lazy) may generate queries the agent did
   not explicitly request. Should the guard evaluate each generated query
   independently?

5. **Connection pooling.** Tool servers typically use connection pools.
   Chio governs at the tool call level, not the connection level. A single
   tool call might execute multiple queries (e.g., a transaction).
   Should the tool server submit all queries in a transaction as a
   single tool call, or each query separately?

6. **Materialized views.** A materialized view may contain data from
   tables the agent is not allowed to query directly. Should view access
   require grants on the underlying tables, or should views be treated
   as their own access target?

7. **Vector embedding model governance.** When an agent upserts
   embeddings, which embedding model was used? A capability could
   constrain which embedding models produce vectors that may be written
   to a collection, preventing model confusion attacks.

8. **Cross-database joins.** BigQuery federated queries and Snowflake
   external tables can join across data sources. A single query might
   access data in two databases with different governance requirements.
   Should the guard decompose the query and evaluate each source
   independently?
