# Plan 94-01 Summary

ARC now projects more than one bounded portable credential profile from the
same `AgentPassport` truth. The issuer metadata surface advertises explicit
portable profile configuration for `application/dc+sd-jwt` and `jwt_vc_json`,
each rooted in the same signing key and lifecycle sidecar model.
