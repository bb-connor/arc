## Task 3: CLI, remote import and product consumer integration

Files: CLI receipt types/dispatch, control-plane receipt handlers, Wall exporter,
Mercury builders/proof-export CLI and their tests.
Interfaces: export --kernel-seed-file; verify/import --trusted-kernel-pubkey
(repeatable), optional --trusted-anchor-file; remote admin import carries separate
verification policy. Generated producers retain their existing in-memory signer.

- [ ] RED: required native CLI flags and end-to-end signer/manifest/anchor attacks.
- [ ] Wire all consumers without reading a trusted key from the input package.
- [ ] GREEN: native export/verify/import and remote administrative route; compile
  all product consumers and run their affected owner tests.
