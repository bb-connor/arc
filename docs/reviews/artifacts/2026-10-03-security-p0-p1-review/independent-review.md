# Independent review disposition

Reviewer: `security_storage_review`, read-only. No Cargo commands or edits.
Candidate: five repair diffs against `a99437b3ea8ef7ea03c7d2926049b27cb140b3c5`.
Final source bytes are pinned in `source-hashes.json`.

## Production repairs

The reviewer traced retention selection/copy/delete and retained export/query
behavior, then inspected the MCP, API-path and automatic paging repairs. The
follow-up source review identified two incomplete cases in the first patch:

- Matching only the signed projection before counting could hide extra source
  or lineage rows in an archive with attacker-replaced DDL.
- Empty route-template captures and repeated separators could reach a different
  upstream handler after slash normalization.

Both cases received failing boundary regressions and production repairs. The
final source verdict accepted all five fixes with no remaining P0/P1 in the
reviewed repair boundaries. It specifically checked counting every source and
lineage candidate, retention revalidation under the destructive transaction,
lifecycle locking through MCP enqueue, decoded route identity and the paging
reference allowlist with severity/filter/dedup behavior preserved.

Limitations retained by the reviewer:

- Historical source cursor assignments are unsigned. This repair establishes
  unique projections in a pinned snapshot, not authenticated ordering across
  adversarial changes between separate pagination requests.
- Broader EV1 privacy, EV2 admission retention and EV15 alert signer admission
  remain open. Direct caller-constructed `Alert` payloads are outside automatic
  receipt-to-alert projection.
- Runtime checks belong to the implementation owner. Source review does not
  establish hosted, release or operational acceptance.

## Fixture follow-up

The reviewer separately accepted the final fixture corrections:

- Approval fixtures install their signer/tenant and bind the exact capability,
  arguments, request and policy before signing. Negative cases retain denial
  before claims, budgets or dispatch.
- Removing the wire DPoP field restores genuinely absent-proof cases. The
  added wire-only positive case proves dispatch and retained custody through
  synchronous and asynchronous entrypoints.
- MCP commits `Ready` after successful initialize and before subsequent
  notifications, matching the production HTTP owner.
- Splunk still proves a real request and a bounded timeout; the public error
  assertion now matches sanitized transport failures.

No production regression or weakened negative coverage was found in these
fixture changes. The reviewer ran `git diff --check`, which passed.

The broad storage campaign subsequently found two more outdated fixtures. A
second read-only follow-up accepted their corrections: threshold requests bind
the actual capability ID and canonical argument hash before proposal creation
and voting, using their existing threshold resolver; the provenance fixture
uses the existing helper to supply the required Unix `0700` parent permissions.
Corruption refusals, exact error assertions, preserved rows and successful
recovery remain unchanged. No builds or tests were run by the reviewer.

## Incomplete independent attempts

Two other read-only review attempts ended before final verdicts. They are not
counted as completed independent coverage. Their preliminary MCP/path findings
were independently traced and reproduced by the implementation owner. The main
review report describes the resulting bounded inline coverage.
