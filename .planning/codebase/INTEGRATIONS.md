# External Integrations

**Analysis Date:** 2026-03-19

## APIs & External Services

**MCP peers:**
- External MCP servers and clients - The core interoperability surface ARC wraps or replaces
  - Integration method: stdio and HTTP transport adapters
  - Auth: Capability tokens plus optional bearer/JWT auth on remote HTTP serving
  - Endpoints used: MCP tool/resource/prompt/completion/logging/session flows

**Live conformance peers:**
- Node- and Python-based harness peers - Used to validate real interoperability claims
  - Integration method: Local subprocesses and HTTP calls during test runs
  - Auth: Test-local only
  - Rate limits: None; local/dev harness usage

## Data Storage

**Databases:**
- SQLite - Durable receipt, revocation, authority, and budget state
  - Connection: File paths passed via CLI flags
  - Client: `rusqlite`
  - Migrations: Schema is managed inside runtime/store initialization code rather than an external migration tool

**File Storage:**
- Local filesystem - Policies, manifests, authority seeds, temp dirs, and example assets
  - SDK/Client: Standard Rust filesystem APIs
  - Auth: OS/user permissions only

**Caching:**
- None currently called out as a major subsystem

## Authentication & Identity

**Capability and receipt identity:**
- Ed25519 keypairs - Capability and receipt signing
  - Implementation: `ed25519-dalek`
  - Token storage: Files or generated in-process depending on workflow

**Remote session auth:**
- Static bearer tokens and optional JWT verification for `serve-http`
  - Implementation: CLI flags and local key files
  - Session management: Session identity is runtime-owned once admitted

## Monitoring & Observability

**Logs:**
- `tracing` to stdout/stderr
  - Integration: Local process logs and CI log capture

**Error Tracking / Analytics:**
- None configured as a dedicated external service in the repo today

## CI/CD & Deployment

**Hosting:**
- Self-hosted Rust binary / local process execution
  - Deployment: Manual local runs or custom hosting around `arc`
  - Environment vars: Limited; most runtime config comes from CLI flags and file inputs

**CI Pipeline:**
- GitHub Actions
  - Workflows: `.github/workflows/ci.yml`
  - Secrets: Not required for the core public CI path shown in the repo

## Environment Configuration

**Development:**
- Required baseline: Rust 1.93+
- Optional for live conformance: `node`, `python3`
- Secrets location: Local files/flags for authority seeds and HTTP auth keys when needed

**Staging / Production:**
- No formal staging profile encoded in the repo yet
- Hosted deployments are still maturing as part of the closing-cycle work

## Webhooks & Callbacks

**Incoming:**
- None as a first-class external webhook product today

**Outgoing:**
- None as a first-class external webhook product today

---
*Integration audit: 2026-03-19*
*Update when adding/removing external services*
