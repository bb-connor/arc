# Security evidence image inputs

`ca-certificates-20260611-r0.apk` is the original Alpine 3.22 x86_64 package
already pinned by this image. It is retained byte for byte because a hosted
build received HTTP 404 from the versioned CDN URL while a local fetch still
returned the expected bytes. This repair does not update the package inventory.

- Origin: <https://dl-cdn.alpinelinux.org/alpine/v3.22/main/x86_64/ca-certificates-20260611-r0.apk>
- Retrieved: 2026-10-05
- Length: 129495 bytes
- SHA-256: `a8ad8f04dfba1a2897388c4b420b698bf1ecd870be10f0127134a567d5e59896`
- Alpine source commit: `5b10c3f23f6d4e588859db153f0949c850d7f8aa`
- Package license metadata: `MPL-2.0 AND MIT`
- Alpine signing key: `alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub`

The original package signature also verifies with APK using the x86_64 public
key from <https://alpinelinux.org/keys/alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub>
(key SHA-256 `207e4696d3c05f7cb05966aee557307151f1f00217af4143c1bcaf33b8df733f`).
That portable signature check does not qualify native enforcement or image
execution. Image installation still uses the base image's own trusted keyring.

The package is mounted read-only during the installation instruction, checked
against its original digest, and verified by APK against the pinned base image's
trusted Alpine keys. APK verification remains mandatory. The resulting complete
229-package inventory must match `security-evidence-apk.lock`. The package archive
is not copied into an image layer. Other pinned downloads remain network inputs;
this change is not a claim that the entire image builds offline.

Changes to this input require reviewing the actual upstream package, its hash,
the resulting complete package inventory and the structural contract together.
Do not substitute a new certificate bundle under the retained package name.
