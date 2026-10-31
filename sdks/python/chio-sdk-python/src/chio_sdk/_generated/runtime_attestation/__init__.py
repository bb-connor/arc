# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 29f505f3691b4fbfea30cc6f60a7264757030799f7d4c23f1b591e15d011a565
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.

from __future__ import annotations

from .appraisal_report_schema import Appraisal, Artifact, ChioRuntimeAttestationAppraisalReportSignedBody, Claims, Evidence, NormalizedAssertions, NormalizedClaim, Policy, PolicyOutcome, Reason, VendorClaims, Verifier
from .appraisal_result_schema import Appraisal, ChioRuntimeAttestationAppraisalResultSignedBody, Claims, Evidence, ExporterPolicyOutcome, NormalizedAssertions, NormalizedClaim, Policy, Reason, Subject, VendorClaims, Verifier, WorkloadIdentity
from .evidence_schema import AwsNitro, AzureMaa, ChioRuntimeAttestationEvidenceSignedBody, Claims, EnterpriseVerifier, Pcrs, WorkloadIdentity
from .reference_values_schema import ChioRuntimeAttestationReferenceValuesSignedBody, Measurements
from .trust_bundle_schema import Body, Body214, ChioRuntimeAttestationTrustBundleSignedBody, Descriptor, Measurements, ReferenceValue
from .verifier_descriptor_schema import ChioRuntimeAttestationVerifierDescriptorSignedBody

__all__ = [
    "Appraisal",
    "Artifact",
    "AwsNitro",
    "AzureMaa",
    "Body",
    "Body214",
    "ChioRuntimeAttestationAppraisalReportSignedBody",
    "ChioRuntimeAttestationAppraisalResultSignedBody",
    "ChioRuntimeAttestationEvidenceSignedBody",
    "ChioRuntimeAttestationReferenceValuesSignedBody",
    "ChioRuntimeAttestationTrustBundleSignedBody",
    "ChioRuntimeAttestationVerifierDescriptorSignedBody",
    "Claims",
    "Descriptor",
    "EnterpriseVerifier",
    "Evidence",
    "ExporterPolicyOutcome",
    "Measurements",
    "NormalizedAssertions",
    "NormalizedClaim",
    "Pcrs",
    "Policy",
    "PolicyOutcome",
    "Reason",
    "ReferenceValue",
    "Subject",
    "VendorClaims",
    "Verifier",
    "WorkloadIdentity",
]
