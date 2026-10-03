# Private-key allocation ownership audit

The initial rustls-pki-types iterator stored encoded private bytes in an ordinary Vec. Its errors could own malformed lines. Both paths were removed for private inputs.

| Path | Allocation ownership and exit |
| --- | --- |
| Private file read | Existing read_private_signing_custody allocates fixed Zeroizing<Vec<u8>>, reads bounded bytes and checks owner/mode/link/opened identity; all exits wipe. |
| Certificate absent/invalid/oversized | Validation returns before private PEM decoding. The caller's private file buffer remains guarded. |
| PEM framing | Lines are borrowed slices of the guarded input. Static KeyKind labels and payload-free PemError own no input. |
| Base64 scratch | Fixed Zeroizing<Vec<u8>> allocated once at input length; bounded stores never grow or reallocate it. Duplicate/trailing blocks reject while this scratch remains guarded, before DER exists. |
| Decode failure | The fixed DER buffer is Zeroizing from allocation, so even a partial decoder write is wiped on error. Decoder errors are projected into the payload-free typed Encoding category. |
| Decode success | truncate discards only initially zero bytes beyond the produced DER. mem::take moves the existing allocation directly into PrivateKeyDer inside Zeroizing; there is no fallible operation between transfer and guard attachment. The compile-time ZeroizeOnDrop test verifies the returned guard contract. |
| Protocol configuration error | The decoded key guard remains live and wipes on return. |
| Provider handoff | Replace the guarded key with an empty key immediately inside with_single_cert's call. In locked rustls0.23.45, CertifiedKey::from_der first invokes the explicit AWS-LC load_private_key, which immediately wraps owned DER in Zeroizing. Success and rejection wipe that DER; the native signing key owns the operational key afterward. |
| Key mismatch | AWS-LC already consumed and wiped DER before certificate/key consistency is checked. The native signing key is dropped with the failed configured identity. |
| Diagnostics | Private PEM parsing never creates input-bearing errors. Certificate parser failures also project into payload-free Framing. Display, Debug and every source are checked for plaintext and decimal private-marker bytes, both directly and through production prepare. |

This is a source ownership audit plus executable boundary controls, not a claim of a post-free heap probe or a native cryptographic-library memory audit. Existing AWS-LC audit/release gates remain separate. Operator-provided PEM is one unencrypted PKCS8, PKCS1 or SEC1 block, permitting whitespace and CRLF; additional records, encrypted keys and trailing text are refused.

## Inspected dependency source identities

- `rustls-pki-types-1.14.0/src/pem.rs`: `0da320e26748162dd7d02df043c911155eb498307a27ec543bd7e00baaed4b77`
- `rustls-pki-types-1.14.0/src/lib.rs`: `8946e5024c684256e15418bffed2aaa553befcc6270b098db293fb67e0a8e25d`
- `rustls-0.23.45/src/crypto/aws_lc_rs/mod.rs`: `e50e9f80fff948d5ed959c408ba89558dc99892fa6297d73fad3062b595db018`
- `rustls-0.23.45/src/crypto/signer.rs`: `b097775c0b30d507255824a8ac65d8d7440e723b16a9e91036e0d096a3d7b071`
- `rustls-0.23.45/src/server/builder.rs`: `4ec5532bbaaf9d60ae2fb577e8f463e2f3f6915aa80d0f11627829214fa7eb8c`
