# Retained uncertain-call fixture

This public signed observation comes from the confined four-worker budget run
identified in `provenance.json`. The host died after Carol appended but before
its tool returned. Recovery refused to repeat that original request. The
retained operation is `outcome_unknown_after_dispatch`; its signed recovery
response is a kernel denial, not a completed tool result.

`kernel.pub` is the independently retained public verification key. No private
key or private retained admission request is included. The artifact is a later
signed readback of the fenced store. Its custody claim does not pretend an
original completed-call commitment exists. This fixture supports offline
signature and semantic regressions; it does not certify all M5 requirements.

`interrupted.json` records the distinct network case: the confined tool exited
before responding. Its original signed receipt is incomplete and retains an
exact continuation commitment. The later store observation retains the unknown
operation and incident. `interrupted-kernel.pub` and
`interrupted-provenance.json` identify the public verification inputs. Neither
fixture claims an unknown external outcome became a completed tool result.
