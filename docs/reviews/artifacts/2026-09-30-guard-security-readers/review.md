# Final source review and resolutions

One read-only reviewer (`guard_security_final_review`) reviewed the 33 pinned
reader paths and supporting changes against base
`90e8f0683b251b49cccbaa6d94d554c53eb88932`. Implementation remained with the parent.
This record reports the review and subsequent fixes; it does not claim a second
independent review of the final fixes.

| Finding | Resolution and production-linked control |
| --- | --- |
| OCI SDK `pull` / `pull_manifest_raw` retained entire manifests and blobs before local checks. | Both download entry points now use the egress-contract transport. Manifests are digest-pinned and capped at 16 MiB; all descriptors are validated before download, config/layers share a 64 MiB budget, and each streamed blob is bounded to its declared size. Real HTTP controls exercise valid download, duplicate original manifest, excessive Content-Length, chunked overflow and descriptor preflight. |
| Vertex could Allow `finishReason: SAFETY` when probabilities stayed below the configured threshold. | Explicit safety finish reasons and rating `blocked: true` now deny. Low-probability real HTTP controls cover both cases. [Provider response contract](https://cloud.google.com/vertex-ai/generative-ai/docs/reference/rest/v1/GenerateContentResponse) confirms both block signals. |
| Initial source integration used the wrong bounded-vector import and changed classification index-conversion errors incorrectly. | The path decoder imports the actual `ports::BoundedVec`; location conversions retain `InvalidLocation`, with typed parser causes only at the JSON boundary. |

The review accepted existing sandbox/bootstrap/status, keyring canonical readers,
AEAD-bound decoy registry, canonical watermark candidates, and quarantine
record/effect/contribution readers as constrained contracts. These are retained,
not represented as new implementations. Security types retain their constructor
and set invariants; the shared vector visitor additionally avoids constructing
an overflow element.

The parent self-review and package campaign also resolved:

- Unsigned embedding vectors use a duplicate-aware document JSON gate, preserving
  ordinary float spellings such as `0.10` and `1.0`. The existing signed and
  external numeric contracts are unchanged, with a control asserting their
  stricter rejection alongside unsigned acceptance. The final guard package is
  rerun after this integration correction.
- Registry forwarding preserves `AttestError::Input` as a native parser cause.
- WASM file errors preserve native IO causes and path context. CLI classification
  and the optional fuzz error census recognize the new variants.
- Complete Azure fixtures match their requested categories. VirusTotal 404 is
  an unknown result and denies; valid explicit zero-threat results still Allow.
- Download concurrency configuration for the removed SDK pull path was removed.
  Downloads are sequential under the aggregate budget; uploads retain their
  concurrency setting. Registry Basic credentials are not delegated to an
  arbitrary token-realm authority.

Parent-directory races, cache/blocklist atomic publication, broader filesystem
ownership, opaque semantic PortError causes, optional platform/backend matrices,
native enforcement, cryptographic protocol requalification, hosted CI and M5
remain outside this reader batch. No claim of release or operator acceptance.
