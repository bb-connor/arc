### Task 1: Truthful receipt semantics and complete HTTP projections

Files: chio-http-core receipt/evaluation and API-protect sidecar submission.
Interface: HttpReceipt::to_chio_receipt_with_keypair preserves the original signed
HTTP record and classification; VerifyReceiptResponse separates validity/authority.

- [ ] Reproduce submitted record authorized=true through /chio/verify and missing
  fields in the core projection. Expected: RED.
- [ ] Implement the closed observation profile, verified original HTTP projection
  and non-authorizing verification. Reject mixed profiles and foreign signers.
- [ ] Run HTTP core and focused API semantic controls. Expected: all pass.
