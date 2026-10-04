AP1 local source implementation

Baseline: 6cf283c4b9e36485a98275ba6798052b01a5a9d0, uncommitted changes.

Shared strict PublicKey parser replaces public-label seed derivation on both mint routes and both alias shapes. Missing/malformed/label/padded and weak Ed25519 subjects reject before token signing or durable store mutation. Public metadata still produces deterministic capability IDs only.

Real production-router controls use the sidecar issuer and caller public key, then real DPoP admission through /v1/evaluate. Caller proof reserves successfully; former public-derived seed, wrong key, stolen token without proof and forged signature advertising caller key deny without authorization nonce. Canonical shorthand formats preserve public subjects but do not enable DPoP; existing bearer behavior explicitly documented.

Kubernetes controller now requires chio.world/subject-public-key Ed25519 hex annotation, preserves it in MintRequest and rejects malformed/missing values before finalizer/grant mutation and mint I/O. Crypto curve and weak-key validation remain authoritative at sidecar. Existing unkeyed Jobs that need grants must migrate; old signed tokens require revocation and remint. No private signer material provisioned automatically.

Verification:
- Rust RED: red.log retained test-only type error; red2.log expected failures (public subject changed, label issuance accepted, old derived DPoP seed reserved).
- Rust GREEN: cargo test --locked -p chio-api-protect, green.log, exit 0: 229 passed, 0 failed, 0 ignored.
- Go RED: go-red2.log expected rejection/identity regression failures. go-red.log retains initial mistaken cwd/concurrent log output.
- Go GREEN: go test ./..., go-green2.log, exit 0 all packages.
- Python initial python-contract.log had wrong expected exception type; corrected test to existing ChioError HTTP_400 mapping without error-map production change.
- Python GREEN: .venv/bin/python -m pytest -q, python-green.log, exit 0: 210 passed.
- rustfmt and git diff --check passed.
- Warnings-denied Clippy delegated to root's affected-package integration graph after KG1.

Limits: This is local verification only. Hermes live CLI fixture public key was migrated but gated runtime not executed. The adjacent Python mint-auth gap is repaired: optional ChioClient(control_token=...) supplies Authorization only to create_capability, not shared HTTP transport headers or health/evaluate. Constructor representation and debug logs omit the token. The gated Hermes fixture configures a random operator bearer through process environment and supplies it to mint clients; no live launch claim. RED missing constructor parameter is retained python-control-red.log; final full SDK GREEN is python-control-green2.log (211 passed), superseding the earlier 210-test result. MockChioClient does not validate curve material; README states this. No hosted, merged, pushed, published or deployed claims. No output/ changes. No commits.
