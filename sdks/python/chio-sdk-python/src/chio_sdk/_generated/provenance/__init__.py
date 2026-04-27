# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 47c14e6bc7f276540f7ae14d78b3cfb7b2b67b0a023df6a65298a2fa4d2b38e5
#
# Manual edits will be overwritten by the next regeneration; the
# M01.P3.T5 spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.

from __future__ import annotations

from .attestation_bundle_schema import ChioProvenanceAttestationBundle, CredentialKind, EvidenceClass, Scheme, Statement, Tier, WorkloadIdentity
from .context_schema import ChioProvenanceCallChainContext
from .stamp_schema import ChioProvenanceStamp
from .verdict_link_schema import ChioProvenanceVerdictLink, ChioProvenanceVerdictLink1, ChioProvenanceVerdictLink2, ChioProvenanceVerdictLink3, ChioProvenanceVerdictLink4, EvidenceClass, Verdict

__all__ = [
    "ChioProvenanceAttestationBundle",
    "ChioProvenanceCallChainContext",
    "ChioProvenanceStamp",
    "ChioProvenanceVerdictLink",
    "ChioProvenanceVerdictLink1",
    "ChioProvenanceVerdictLink2",
    "ChioProvenanceVerdictLink3",
    "ChioProvenanceVerdictLink4",
    "CredentialKind",
    "EvidenceClass",
    "Scheme",
    "Statement",
    "Tier",
    "Verdict",
    "WorkloadIdentity",
]
