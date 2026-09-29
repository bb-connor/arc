# Fresh final review

Candidate: `53858afa39`, base: `1d4f3b4ad3`. One read-only fresh-context review
using `gpt-6-astra`, high reasoning; no reviewer subagents or repeated suites.
The review judged the candidate ready only with fixes. No Critical findings.

## Important findings

1. `chio-a2a-adapter/src/oauth_cache.rs`: lookup samples before taking the cache
   mutex. Concurrent T1/T2 samples can acquire the mutex in reverse order and
   falsely report a healthy clock as regressing. Sample and update observations
   under the same cache lock.
2. `chio-a2a-adapter/src/invoke.rs`: acquisition checks advertised expiry before
   the cache store's later observation. Expiry at that later observation only
   suppresses caching, so acquisition can still return the expired token. Validate
   full advertised lifetime and optional cache lifetime at the final observation.
3. `chio-mcp-adapter/src/transport/stdio_writer.rs`: an expired queued command
   terminates the shared writer even though no OS write failed, dropping later
   healthy commands and closing stdin. Expiry must reject only that command.
4. `chio-mcp-adapter/src/transport/nested_flow.rs`: capacity reclamation removes
   unexpired terminal tasks and destroys results that have not been collected.
   Reject admission until capacity is freed by expiry or acknowledged release.

## Initially Minor findings

- The MCP edge channel converted typed decoder failures to strings, losing the
  local cause on a production path. The executor promoted this to Important
  because the approved error-source contract covers actual consumers.
- An older architecture paragraph described oversized frames being drained and
  continuing, contradicting the new terminal behavior. The executor corrected
  it as part of documenting the changed contract.

## Declined to judge

- Preexisting native legacy launch removal and wider semantic-error migration:
  already assigned to the next batch.
- Preexisting edge terminal-task eviction: the executor elected to apply the
  same result-custody fix to both task owners.
- Workspace, hosted, release and operator qualification: outside the local
  review and unsupported by its evidence.

The executor's dispositions, their costs and fix verification are retained in
[execution-ledger.md](execution-ledger.md). No second reviewer was dispatched.
