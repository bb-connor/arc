## Task 2: Signed package envelope and unified verification

Files: control-plane evidence_export/{envelope,verification,package_io}.rs and
existing export types/writer; dedicated package trust tests.
Interfaces: SignedExportEnvelope, EvidenceVerificationPolicy; manifest and decoded
payload hashes; load_verified_evidence_package(input, policy), structured import
validation(package, policy); writer consumes the existing kernel keypair.

- [ ] RED: missing envelope, substituted signer, rewritten manifest/omitted record,
  divergent decoded payload, receipt/checkpoint key mismatch and wrong anchor.
- [ ] Implement schema/domain binding, complete required-file inventory, bounded
  readers, trusted signer set, proof key binding and full anchor descriptor match.
- [ ] GREEN: positive multi-record package and all adversarial controls; authentic
  advisory/uncheckpointed records keep their narrower evidence claims.
