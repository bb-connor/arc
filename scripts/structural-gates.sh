#!/usr/bin/env bash
# Sourced by CI. Each gate runs in its own process and contributes a terminal
# result even when an earlier gate failed. Call finish_gates as the last command.
CHIO_GATE_COUNT=0
CHIO_GATE_FAILURES=0

run_gate() {
  local status=0 command
  printf -v command '%q ' "$@"
  CHIO_GATE_COUNT=$((CHIO_GATE_COUNT + 1))
  printf '::group::%s\n' "$command"
  "$@" || status=$?
  printf '::endgroup::\n'
  printf 'gate exit=%s: %s\n' "$status" "$command"
  if (( status != 0 )); then
    CHIO_GATE_FAILURES=$((CHIO_GATE_FAILURES + 1))
  fi
  return 0
}

finish_gates() {
  printf '%s gates, %s failures\n' "$CHIO_GATE_COUNT" "$CHIO_GATE_FAILURES"
  (( CHIO_GATE_COUNT > 0 && CHIO_GATE_FAILURES == 0 ))
}
