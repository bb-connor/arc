# Phase 31 Plan 02 Summary

## What Changed

- introduced ARC-first hosted-runtime environment variables for session
  lifecycle tuning and kept `ARC_MCP_SESSION_*` aliases as documented
  compatibility fallbacks
- updated hosted-runtime tests so ARC names are the default path and legacy
  alias behavior is still covered explicitly
- refreshed operator migration docs so alias, freeze, and compatibility-cycle
  behavior are stated directly instead of being implied

## Result

Operators now have one canonical ARC runtime naming surface, while older
deployments still continue through a controlled compatibility window.
