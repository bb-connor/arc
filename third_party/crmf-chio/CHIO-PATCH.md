# Chio CRMF recursion repair

This fork backports RustCrypto's tag-dispatch repair to the selected 0.2.0 API.
The registry package is not certified by this local source selection.

- Original release commit: `9023db5ddc882cc844d952ae7f74775f3aae797f`.
- Registry archive SHA-256: `36fe21b96d5b87f5de4b5b7202ec41c00110ac817ce6728fe75fb2fe5962ed92`.
- Upstream repair: [2f3e06651769300f8ffa2e04d887e4c8ab7ed16a](https://github.com/RustCrypto/formats/commit/2f3e06651769300f8ffa2e04d887e4c8ab7ed16a).
- License: MIT OR Apache-2.0, original license texts retained.

The only production change is the upstream expression delegating
`EncKeyWithIdChoice::GeneralName` to the contained value's `tag()` instead of
recursively calling itself. The original library aborts with stack overflow on
an ordinary DNS-name value. Chio reachability of that method is not established.

The manifest marks the fork unpublished and independently testable. Upstream
tests are retained. Their missing sibling CMS fixture is copied from the
checksum-verified cms 0.2.3 archive, and the include path is made self-contained.
New tests cover DER encoding and decoding of primitive and constructed name
variants, the UTF-8 alternative and rejection of an unrelated tag.

```sh
cargo test --locked --all-features --manifest-path third_party/crmf-chio/Cargo.toml
```

The original abort, upstream repair and test results are retained under
`output/process-security-20260915/asn1-dependency-audit-e271c26a6/`.
