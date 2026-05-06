# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
<<<<<<< HEAD
# Schema sha256: e22b26006c4ad64cb91683eb774882242236c16e94fa59e56793f01203f2304c
=======
# Schema sha256: 78f3823cf6fa1cdb5631939980d1e7f2ac23856bfa1d85734671809e66bef0e7
>>>>>>> 41493c3a3 (fix(spec): make schema field optional in v1 token schema)
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.

from __future__ import annotations

from .attestation_schema import ChioTrustControlRuntimeAttestationEvidence, CredentialKind, Scheme, Tier, WorkloadIdentity
from .heartbeat_schema import ChioTrustControlLeaseHeartbeat
from .lease_schema import ChioTrustControlAuthorityLease
from .terminate_schema import ChioTrustControlLeaseTermination, Reason

__all__ = [
    "ChioTrustControlAuthorityLease",
    "ChioTrustControlLeaseHeartbeat",
    "ChioTrustControlLeaseTermination",
    "ChioTrustControlRuntimeAttestationEvidence",
    "CredentialKind",
    "Reason",
    "Scheme",
    "Tier",
    "WorkloadIdentity",
]
