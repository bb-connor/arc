# Rust 1.95 execution image inputs

Updated October 7, 2026.

The current guard runtime uses the supported Wasmtime 48.0.5 repair, whose
upstream minimum is Rust 1.95.0. The workspace minimum, pinned toolchain,
current MSRV/build lanes and five production Docker builders now agree on
that deliberate migration. The root, standalone fuzz and generated CLI-only
Docker Cargo graphs all resolve Wasmtime 48.0.5 and the reviewed unpublished
cpp_demangle 0.5.1 path source. See
[the runtime migration review](../../supply-chain/reviews/wasmtime-runtime-upgrade.md).

The production Alpine builders and the security evidence runner use the
official Rust 1.95.0 Alpine 3.22 index
`sha256:064dfc925d68d1a63f4fd2871bd7dc6e6ea56692989a487185855d62885d90aa`.
The GNU production builders use the official Rust 1.95.0 Bookworm Slim index
`sha256:d7482085ff5b415f84dba5647ae71606650bdef00db7aeb69f4b3d170c3e4082`.
Both index bodies, their amd64/arm64 descriptors and their image configuration
payloads were downloaded and matched against their actual SHA-256 addresses.
The image configuration and
[official source revision](https://github.com/rust-lang/docker-rust/tree/dd106de2954f52f336c3d2c1326ae778c51830f3/stable)
agree on Rust 1.95.0. These are source and digest checks; they do not establish
a completed build of every production image.

The security runner's Clippy and rustfmt archives were downloaded from the
official April 16, 2026 distribution and matched to the official 1.95.0
distribution manifest. Their SHA-256 values are
`c55a7b5604fe2e0400911c488b320922066fe23646235793cec7c8e5c03e7a61`
and `688a9ba3b40e9fd360dc083ff28b7ae43c110f2919ee939bb788a46a1e579a84`.
The Dockerfile still compares the installed binaries with those archive
payloads and checks their exact reported versions. This local record checks
official HTTPS provenance and byte hashes; it does not claim a local OpenPGP
verification of that distribution manifest.

An actual amd64 installation over the new immutable base produced the exact
225-package inventory now committed in `deploy/docker/security-evidence-apk.lock`,
SHA-256 `2094807ad2bfeb1dc61c5c8d2ea7fec92735fa908f64ede7bb93f1ceeb5e20f2`.
The former CA archive returns HTTP 404 from its configured primary repository.
The selected replacement is `ca-certificates 20260909-r0`, archive SHA-256
`a1258993a229d2fdcc6d9665af75c9305184e4f5e5755c50b9ef0564b35138c4`.
Current OpenSSL and Python pins are `3.5.9-r0` and `3.12.15-r0`.
The entire installed inventory and its hash remain mandatory checks. No
package, component, source-binding or execution-authority check was removed.

The genuine successor archive manifest is
`deploy/docker/security-evidence-apk-archives-rust195.json`, SHA-256
`1ff35429db256dcc11b5b42d481e53b4e5b30fa394ae5ba05616b8c7711bab29`.
Its 199 downloaded archives have actual package-info names and versions equal
to the selected installation; 26 packages remain unchanged from the immutable
base. A fresh `docker run --network none` with `apk add --no-network` and
default signature authentication produced the same exact 225-package lock
and inventory hash. The two preceding failed archive-fetch attempts remain
separate failed records.

The retained local provenance and qualification commands are under
`target/recovery-pr/dependency-security/rust195-container-review/`.
Archive retention, offline replay, the complete security image build and actual
image boundary probes have independent result records. The attempted full
amd64 build under QEMU failed when `cc` received SIGSEGV while linking
`clap_derive` for the pinned `cargo-mutants` source. It produced no completed
security runner image. The toolchain-only diagnostic image is separate and
cannot establish trusted capture qualification. Those failed and diagnostic
records remain intact.

The subsequent native amd64 build completed successfully in 240.6 seconds,
using the unchanged recipe and frozen context SHA-256
`2644a68905d837f6851db3aedb488da62bb43db6daf21f81c1cd0736988d7d3a`.
Both ends verified all 39,165 source payloads and the 62 recorded dependency
source pins before building. The actual completed image is
`sha256:44db90adf93bb74cb7be8b8dd5d2da1ad42908ea910be8535f3b2a41f0444ab3`.
Its retained Docker archive is 4,713,062,400 bytes, SHA-256
`9ce801b0f3bd04e6b1a9c20408c28f27b62134aec7eb440c21feeaafcecce420`.
All 11 saved layer hashes match the image configuration; its first three
layers match the verified official amd64 base configuration. No retained
repository paths or copies of four unique complete source files were found
in any layer. This bounded scan does not prove the absence of arbitrary
transformed or fragmentary data.

The actual image reports the exact Rust, Cargo, Clippy, rustfmt and
cargo-mutants versions, contains the exact 225-package inventory, and has
14 root-owned authority payloads equal to their reviewed source bytes and
permissions. A fresh read-only image run as UID 1001, with networking disabled,
completed `cargo fetch --locked --offline` and independently matched all
1,198 root-lock registry archives to their declared checksums.

Docker 29 returned the two exact bind mounts in a different array order.
The independently reviewed host-runner repair checks every field, key, type,
count and distinct destination before comparing the complete dictionaries in
canonical destination order. Its CI verifier pins the exact semantic guard
through the existing stable AST normalizer. The four-file host runner,
verifier and test overlay was staged separately; the other 39,161 frozen
payloads, image and 14 embedded authority payloads remain unchanged.
The actual Docker hostile fixtures passed with normal and optimized Python,
including the required init process. The full GNU verifier mutation suite
passed as UID 1001 in 500.183 seconds. The builder's init executable was
matched to the authenticated Docker package; the preceding missing-init
startup failure remains a separate failed prerequisite record.

These results qualify the exact standalone image and reviewed host overlay.
They do not qualify later runtime or compiler-capture source changes, every
production image, a hosted release, or an execution-authority rotation.
No registry image was published. The exclusive guest lease ended at
20:53:02 UTC on October 7 with zero owned workloads, unchanged default FD
limits, and the image, caches, archives and earlier failed attempts retained.
Final commands, results and input bindings are under the provenance directory's
`native-amd64/final-received/` subdirectory.

[The September image evidence](execution-image-inputs-2026-09-20.md) and
`deploy/docker/security-evidence-apk-archives.json` describe their historical
inputs. Their former toolchain, package archives, lock digests, failures and
image identifiers remain historical evidence. They do not qualify this new
recipe. Confidence is high in the reviewed source, provenance and executed
standalone checks; current runtime, hosted and cross-platform release
qualification remain separate.
