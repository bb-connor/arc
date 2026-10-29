<!--
Target: spec/PROTOCOL.md
Insertion point: new subsection after "### 4.4 Identity", before "## 5. Capability Contract".
Move the text below this comment into place unchanged; drop this comment.
-->

### 4.5 Signing Wrapper

Status: specified, not implemented. Implementations emit and accept the formats in the sections this one names until this line is removed.

Sections in force until then: 4.1 (signatures over the canonical body), "WYSIWYS Signing Invariant" and "Receipt Identity And DAG" in section 6.

Every Chio signature over bytes Chio defines signs an 88-byte signing wrapper
instead of the body. This covers capabilities, delegation links, Chio DPoP
proofs, receipts, settlement closures, root policies, identity-provider key
snapshots, checkpoints, export commitments, readiness probes, challenges and
every other artifact in the Signed-Artifact Registry (section 5).

```text
wrapper = "chio.signing-wrapper.v1" || 0x00          (24 bytes)
       || SHA-256(utf8(schema_id))                     (32 bytes)
       || SHA-256(canonical_body)                      (32 bytes)
```

Rules:

- `schema_id` is the signed artifact's registered schema id, never the id of
  a payload or body schema. Each signed artifact has exactly one id, and a
  request and its response are two artifacts with two ids. Where an artifact
  carries a `schema` member, it equals the wrapper id. A verifier takes
  `schema_id` from its verification context, meaning the artifact type it
  expects at that call site. It never reads `schema_id` from a member of the
  artifact being verified. A signature over one artifact type therefore never
  verifies as another.
- `canonical_body` is the RFC 8785 canonical JSON of the artifact's signing
  body. For receipts it is the canonical
  `ChioReceiptSigningBody { id, body, bbs_signature? }`, so BBS signature
  material stays covered by the authoritative signature through this hash.
- The schema id is the only signature domain separation. No signing input
  carries a domain prefix of its own. A body that is signed together with its
  signer's key is the object `{"body": <body>, "signer": <key>}`. A signature
  that would cover a digest of a Chio object covers the wrapper over that
  object's canonical body instead. Domain strings inside hash and commitment
  inputs (digests, identifiers, commitments) are not signature prefixes and
  are unaffected.
- Domain separation: no Chio key signs any message other than wrapper bytes,
  except the local authorization server key, which signs JWS signing inputs.
  A JWS signing input is base64url text plus `.` and never contains `0x00`.
  Byte 23 of every wrapper is `0x00`, so the two message spaces are disjoint.
  The local authorization server key is still required to differ from every
  wrapper-signing key (section 5.6).
- Algorithm binding: every pinned key admits exactly one signature algorithm,
  derived from its self-describing encoding (section 4.4). A signature whose
  prefix does not match the pinned key's algorithm rejects before any
  cryptographic check. A verifier holding a pinned hybrid key rejects a bare
  classical signature.
- Algorithm selection: a verifier derives the signature algorithm only from
  the pinned, typed key it verifies against. It never reads the algorithm
  from any member of the artifact being verified, signed or unsigned, and no
  member of an artifact changes which verifier runs. Signed artifacts carry
  no `algorithm` member: the top-level `algorithm` member that capability
  tokens, receipts and other envelopes carried outside the signing body is
  removed. An artifact that carries an `algorithm` member, added or altered,
  fails strict decoding before any verifier is chosen.
- Strict decoding: every artifact defined in sections 5.6, 6 ("Committed
  Receipts And Disclosure"), 6.1 (`pdp_decision` receipts) and 6.7 rejects
  an unknown member at every nesting level, even when the signature over the
  body that carries it verifies. This covers `root_anchor` and the capability
  body, the delegation context, the root policy, the identity-provider key
  snapshot, the provider identity projection, the capability presentation,
  the receipt disclosure document, the receipt's commitment, `disclosure`,
  `authority`, `enforcement` and `settlement` blocks and the metering and
  runtime-attestation blocks carried beside them, the settlement closure and
  the caller revocation request. A tagged union rejects an unknown member in
  every variant, including variants that carry only the discriminator: a
  document such as `{"kind": "<variant>", "pad": 0}` rejects.
  Implementations do not decode these unions as serde internally tagged unit
  variants, which accept such padding; a closed discriminator is a string
  member of a closed object, and a union whose variants carry different
  members decodes as closed per-variant objects or through a lossless round
  trip in which the decoded value re-encodes to exactly the input value.
  Duplicate member names reject. Members whose value is caller data by
  definition (an opening's `payload`, `parameters_inline`, `result_inline`,
  `metadata`) are opaque values; the rule covers every Chio-defined object
  around them.
- Ed25519 signs the 88 wrapper bytes.
- ML-DSA-65 signs the 88 wrapper bytes with an empty FIPS 204 context string.
- P-256 signs with ECDSA over SHA-256 of the wrapper. P-384 signs with ECDSA
  over SHA-384 of the wrapper. A remote signer may therefore be sent the
  digest instead of the message.
- Hybrid signatures sign the same 88 bytes with both halves.
- Both inner hashes are SHA-256, which caps the collision resistance of every
  signature at 128 bits, including P-384 and ML-DSA-65. Changing either hash
  or the layout requires a new prefix string and a change to this section.
- Signature encodings are unchanged: bare 128-hex Ed25519, `p256:<DER hex>`,
  `p384:<DER hex>` and the hybrid form of section 4.4.
- Exempt formats, a closed list: JWS signing inputs (RFC 7515, including
  local authorization server access tokens, other JWTs and SD-JWT), DSSE
  pre-authentication encoding, Sigstore Rekor entries and HTTP message
  signatures (RFC 9421). An external standard fixes their signing bytes, so
  they do not use the wrapper. Every other signature does.
- Implementations expose one signing helper and one verification helper for
  the wrapper. No path signs a canonical body directly. Generic signing
  helpers in the SDKs and bindings take the schema id as an argument and
  reject an unregistered id; no helper signs raw caller text.
- The key-log event authorizations (bootstrap, old key, new key proof of
  possession, recovery) all sign `chio.key-log.event.v1`. Each is checked
  against a distinct expected key, and each states the same thing: the key
  approves this exact event body.

Every signing preimage is 88 bytes, so no remote signer's message-size limit
constrains any artifact.

Wrapper schema ids, one per signed artifact type:

| Signed artifact | Wrapper `schema_id` |
|---|---|
| `CapabilityToken` | `chio.capability.v1` |
| `DelegationLink` | `chio.delegation-link.v1` |
| `GovernedUpstreamCallChainProof` | `chio.governed-upstream-call-chain-proof.v1` |
| `CallChainContinuationToken` | `chio.call_chain_continuation.v1` |
| `GovernedApprovalToken` | `chio.governed-approval-token.v1` |
| `ThresholdApprovalProposal` | `chio.threshold-approval-proposal.v1` |
| `SignedDeclassificationGrant` | `chio.declassification-grant.v1` |
| `ChioReceipt` | `chio.receipt.v1` |
| `ChildRequestReceipt` | `chio.child-request-receipt.v1` |
| `ReceiptLineageStatement` | `chio.receipt_lineage_statement.v1` |
| `SignedExportEnvelope<T>` | the schema id of the payload type `T` |
| `SignedRecoveryGrant`, `SignedAuthorityCoverageAttestationV1`, `SignedRecoveryProviderFinalityV1` | `chio.recovery.grant.v1`, `chio.recovery.authority-coverage.v1`, `chio.recovery.provider-finality.v1` |
| `SignedSecurityEvent` | `chio.signed-security-event.v1` |
| `SessionAnchor` | `chio.session_anchor.v1` |
| `AnchorBatch` | `chio.anchor_batch.v1` |
| `SignedClearingEnvelopeV1<T>` | the clearing schema id of the payload type `T` |
| `SignedAssignmentAgreementV1` | `chio.factor.assignment-agreement.v1` |
| `IouEnvelope` | `chio.credit.iou-envelope.v1` |
| `SignedCreditFacilityBindV1` | `chio.credit.facility-bind.v1` |
| `SignedReceivableIou` | `chio.credit.receivable-iou-envelope.v1` |
| `Finding` | `chio.finding.v1` |
| `ChannelSignatureV1` | `chio.channel.signature.v1` |
| `OracleConversionEvidence` | `chio.oracle-conversion-evidence.v1` |
| `SignedAdmissionTerminalProjectionV1` | `chio.signed-admission-terminal-projection.v1` |
| `SignedAuthorityTransition` | `chio.authority-lifecycle.v1` |
| `SignedAuthoritySnapshot` | `chio.authority-snapshot.v1` |
| `SessionComplianceCertificate` | `chio.session-compliance-certificate.v1` |
| `DpopProof` | `chio.dpop_proof.v1` |
| `SignedExecutionNonce` | `chio.execution_nonce.v1` |
| `ActiveResponseSubmissionProof` | `chio.active-response-submission.v1` |
| `ActiveResponseArtifactAuthorityAttestation` | `chio.active-response-artifact-authority-attestation.v1` |
| `SignedContainerLaunchRecord` | `chio.process.container-launch.v1` |
| Swarm delegation-witness hop signature | `chio.swarm.delegation-witness-hop-signature.v1` |
| `SwarmTaskGraph` | `chio.swarm.task-graph.v1` |
| `SwarmContinuationToken` | `chio.swarm.continuation-token.v1` |
| `SwarmJoinReceipt` | `chio.swarm.join-receipt.v1` |
| `SwarmRoutePlanReceipt` | `chio.swarm.route-plan-receipt.v1` |
| `SwarmRevocationEpoch` | `chio.swarm.revocation-epoch.v1` |
| `SwarmTerminalGraphReceipt` | `chio.swarm.terminal-graph-receipt.v1` |
| `SignedCertificationCheck` | `chio.certify.check.v1` |
| `FederationPolicyDocument` | `chio.federation-policy.v1` |
| `SignedActiveResponseAuthorityRequest` | `chio.active-response-policy-authority-request.v1` |
| `SignedActiveResponseAuthorityResponse` | `chio.active-response-policy-authority-response.v1` |
| `SignedManifest` | `chio.manifest.v1` |
| `SignedBudgetSnapshotAnchorCommitment` | `chio.budget-snapshot-anchor-commitment.v1` |
| `EnterpriseMigrationTransition` | `chio.enterprise-migration-transition.v1` |
| `TransactionPassport` | `chio.transaction-passport.v1` |
| `Signed<Subdivision>`, `Signed<WorkOffer>`, `Signed<Selection>`, `Signed<DispatchPermit>` | `chio.work-subdivision.v1`, `chio.work-offer.v1`, `chio.work-selection.v1`, `chio.work-dispatch-permit.v1` |
| `WorkflowReceipt` and its vendor co-signature | `chio.workflow-receipt.v1` |
| `FederatedDelegationPolicyDocument` | `chio.federated-delegation-policy.v1` |
| Proof-room trust roots and guard report | `chio.proof.first-run.trust-roots.v1`, `chio.proof.first-run.guard-report.v1` |
| `SignedMcpCageLaunchPolicy` | `chio.mcp.cage-launch-policy.v1` |
| `SignedProfile` (swarm profile) | `chio.process.swarm-profile.v1` |
| `AgUiReceipt` | `chio.ag-ui-receipt.v1` |
| Operator approval `SignedRecord` | `chio.mcp.operator-approval.v1` |
| Session credential row | `chio.mcp.session-credential.v1` |
| Session credential call row | `chio.mcp.session-credential-call.v1` |
| `SignedProvenance` | `chio.provenance-stamp.v1` |
| `SignedWatermarkEnvelope` | `chio.signed-watermark-envelope.v1` |
| `SignedKeyLogCheckpoint` | `chio.key-log.checkpoint.v1` |
| `SignedKeyActivationCommit` | `chio.key-log.activation-commit.v1` |
| Key-log witness signature | `chio.key-log.witness-statement.v1` |
| `SignedKeyEnterpriseReceipt` | `chio.key-log.enterprise-receipt.v1` |
| `SignedKeyLogEvent` authorizations | `chio.key-log.event.v1` |
| `WitnessServiceReadinessProof` | `chio.key-log.witness-readiness.v1` |
| `AuditServiceReadinessProof` | `chio.key-log.audit-readiness.v1` |
| `KeyringArtifactSignature` fence statement | `chio.keyring.artifact-signature.v1` |
| `SignedArtifactTimeAnchor` | `chio.key-log.artifact-time-anchor.v1` |
| `SignedBrokerAuditRunnerAuthorization` | `chio.broker-audit-runner-authorization.v1` |
| `SignedBrokerAuditComparison` | `chio.broker-audit-comparison.v1` |
| `SignedAuthorityRequest` (broker authority RPC) | `chio.broker-authority-request.v1` |
| `SignedAuthorityResponse` (broker authority RPC) | `chio.broker-authority-response.v1` |
| `SignedBrokerCapability` | `chio.broker-capability.v1` |
| `SignedBrokerPrivilegedAuditChallenge` | `chio.broker-privileged-audit-challenge.v1` |
| `RequestProof` | `chio.broker-request-proof.v1` |
| `SignedAdminMutationReceipt` | `chio.broker-admin-mutation-receipt.v1` |
| `SignedAdminControlReceipt` | `chio.broker-admin-control-receipt.v1` |
| `SignedBrokerReceipt` | `chio.broker-execution-receipt.v1` |
| `SignedBrokerFailureReceipt` | `chio.broker-execution-failure-receipt.v1` |
| `SignedRegisterAttemptAuthorization` | `chio.broker-register-attempt-authorization.v1` |
| `SignedObservation` | `chio.trace-observation.v1` |
| `ReputationCredential` | `chio.reputation-credential.v1` |
| `SignedCrossIssuerMigration` | `chio.cross-issuer-migration.v1` |
| `SignedPublicIssuerDiscovery` | `chio.public-issuer-discovery.v1` |
| `SignedPublicVerifierDiscovery` | `chio.public-verifier-discovery.v1` |
| `SignedPublicDiscoveryTransparency` | `chio.public-discovery-transparency.v1` |
| `FinancialCredentialEnvelope` | the `chio.fincred.*.v1` id of the credential family |
| `FinancialPassportPresentationResponse` | `chio.financial-agent-passport-presentation-response.v1` |
| `PassportPresentationResponse` | `chio.agent-passport-presentation-response.v1` |
| `SignedPassportVerifierPolicy` | `chio.passport-verifier-policy.v1` |
| `PasskeyCapability` | `chio.passkey-capability.v1` |
| `DisclosureCryptoContextReport` | `chio.disclosure.crypto-context-report.v1` |
| `DkgPackage` transport signature | `chio.frost.dkg-package.v1` |
| `RelayAlertAssuranceArchivePackageManifest` | `chio.pheromone.relay-alert-assurance-archive-package-manifest.v1` |
| `RelayAlertAssuranceExportManifest` | `chio.pheromone.relay-alert-assurance-export-manifest.v1` |
| `PeerDirectoryBundleDocument` | `chio.pheromone.peer-directory-bundle.v1` |
| `PheromoneRelayHttpRequest` | `chio.pheromone.relay-http-request.v1` |
| `PheromoneDeposit` | `chio.pheromone-deposit.v1` |
| `TeeBlessAuditEntry` | `chio.tee-bless-audit.v1` |
| tool-server ack | `chio.runtime.tool-server-ack-signature.v1` |
| public settlement proof bundle | `chio.web3-settlement-proof-bundle.v1` |
| checkpoint statement | `chio.checkpoint_statement.v1` |
| payment lifecycle | `chio.commerce.payment-lifecycle.v1` |
| provider-trust artifacts | `chio.commerce.provider-passport.v1`, `chio.commerce.reputation-snapshot.v1`, `chio.commerce.federation-trust-bundle.v1` |
| enterprise approval case | `chio.enterprise.approval-case.v1` |
| risk comptroller report | `chio.risk.comptroller-report.v1` |
| trust-market artifacts | the registered schema id of each trust-market artifact |
| agent-web envelope | `chio.agent-web-proof-envelope.v1` |
| Root policy | `chio.root-policy.v1` |
| Identity-provider key snapshot | `chio.idp-key-snapshot.v1` |
| Settlement closure | `chio.settlement-closure.v1` |
| Caller revocation request | `chio.revocation-request.v1` |
| Evidence export commitment (`SignedExportEnvelope` payload) | `chio.evidence_export_commitment.v1` |
| Aggregate budget root binding | `chio.aggregate-budget-root.v1` |
| Cumulative approval root binding | `chio.cumulative-approval-root.v1` |
| Economic state batch | `chio.economy.state-batch.v1` |
| Economic state anchor view | `chio.economy.anchor-view.v1` |
| Effect dispatch commit | `chio.economy.effect-dispatch-commit.v1` |
| Operation execution nonce | `chio.operation_execution_nonce.v1` |
| Caller dispatch authorization | `chio.caller-dispatch-authorization.v1` |
| Caller delivery report | `chio.caller-delivery-report.v1` |
| Stop operator configuration | `chio.stop-operator-config.v1` |
| Stop operator configuration approval | `chio.stop-operator-config-approval.v1` |
| Channel terminal outcome commitment | its existing schema constant |
| Signer readiness probe | `chio.signer-readiness-probe.v1` |
| Finding-pool store identity proof | `chio.finding-pool.store-identity-proof.v1` |
| ACP-Client compliance certificate | `chio.compliance.certificate.v1` |
| Federation kernel handshake | `chio.federation-kernel-handshake.v1` |
| Any other artifact type added to the Signed-Artifact Registry | its id in `spec/schemas/registry.json` |

A signed artifact type with no registered schema id cannot be signed or
verified. Every id in this table is listed in `spec/schemas/registry.json` and
`KNOWN_SIGNED_ARTIFACT_SCHEMAS` before an implementation emits it, and the
verification helper refuses any id outside that list.
