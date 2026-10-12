# Security evidence image inputs

The security evidence image installs its Alpine packages only from the
archives committed in `security-evidence-apks/`. The package installation
reads no Alpine package index and fetches nothing from the Alpine CDN.

## Closure

- Base image: `rust:1.95.0-alpine3.22@sha256:064dfc925d68d1a63f4fd2871bd7dc6e6ea56692989a487185855d62885d90aa`, linux/amd64, Alpine 3.22.4, apk-tools 2.14.9,
  30 installed packages.
- Installed inventory: 229 packages in `security-evidence-apk.lock`,
  SHA-256 `b2f8548a3f724f94d664e215af35dcab952dabc1cdbd6ee334a872d222d1ff35`.
- Vendored archives: 203, exactly the installed inventory minus the
  26 base packages that stay unchanged. That is
  199 new packages plus upgrades of
  ca-certificates, libcrypto3, libssl3, zlib.
  Total 88,448,457 bytes.
- Manifest: `security-evidence-apks/SHA256SUMS`, SHA-256 `c33666f5f02584d643496c747685dcba26b1b17165a011de380bf3aecfeecd12`.
- Provenance: `security-evidence-apk-archives.json`, SHA-256
  `19c88e47ba275c0a88cdd1beae05818418ea47a7b52a969bd3ed59836c1d4fce`. It records, per archive, the
  name, version, length, SHA-256, origin URL, retrieval date, signing key,
  Alpine source package, aports commit and license, plus the base inventory
  and the reviewed direct packages.

## Origin and signatures

Every archive is the unmodified file served at
`https://dl-cdn.alpinelinux.org/alpine/v3.22/main/x86_64/<archive>`. 202 archives were retrieved on
2026-10-07. `ca-certificates-20260611-r0.apk` was retrieved on 2026-10-05 and is kept byte for
byte: the v3.22 index no longer lists that revision, and a hosted build has
received HTTP 404 for it.

Each archive keeps its original Alpine signature by
`alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub` (key SHA-256 `207e4696d3c05f7cb05966aee557307151f1f00217af4143c1bcaf33b8df733f`, published at <https://alpinelinux.org/keys/alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub>).
`apk verify` inside the pinned base image, with networking disabled, accepts
all 203. The archives are not modified, re-signed or re-compressed.
The license column below is the `license` field of each archive's `.PKGINFO`.

## Installation

The install instruction mounts `security-evidence-apks/` read-only, checks
the manifest against its pinned digest, requires exactly 204 directory
entries (203 archives and the manifest), runs `sha256sum -c` over every
archive, and installs the listed archives with
`apk add --no-network --no-cache --repositories-file /dev/null`. APK
signature verification against the base image's trusted keys stays
mandatory and `--allow-untrusted` is never used. The complete installed
inventory must then equal the lock byte for byte, and the lock must equal its
pinned digest. The archives are not copied into an image layer.

The clippy, rustfmt and cargo-mutants downloads and `cargo fetch` remain
network inputs. This is not a claim that the whole image builds offline.

## Refreshing

Changing any archive requires fetching the exact revision set from the
Alpine repository, verifying it with `apk verify` inside the pinned base
image, regenerating the manifest, provenance and lock together, and reviewing
the structural contract in `scripts/check-security-ci-contract.py`. Never
replace bytes under an existing archive name.

## Archives

| Archive | Length | SHA-256 | Source package | aports commit | License |
| --- | ---: | --- | --- | --- | --- |
| `abseil-cpp-20240722.1-r1.apk` | 15285 | `433f60e4d7df2499b8125b419d71cf59c57830ec426720d96af8dd7c5f821509` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-atomic-hook-test-helper-20240722.1-r1.apk` | 3057 | `e3233b59ed80d7ecef1a03e729d3a7db49b81a78966b651ec02a0a6b908d4348` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-bad-any-cast-impl-20240722.1-r1.apk` | 2768 | `b4d0316c78b00143be9958b3241fd262c99c2718711f2888d873b8a1a2c734c4` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-bad-optional-access-20240722.1-r1.apk` | 2766 | `8fa269b3fb556f7281de9f3099a680d9e0a135b63be832b6a9a772b1c90492f2` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-bad-variant-access-20240722.1-r1.apk` | 2766 | `1fcd7a317801d27bbbc232cd3193232c03ebc5a11539265ccefa7005bd3b9167` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-base-20240722.1-r1.apk` | 8591 | `b65d2898de92bd5153175051852889ad981330f6dc3bdb33863e582d4e62c95b` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-city-20240722.1-r1.apk` | 5215 | `a19a8d0ca66a8251a93db3689600da91d0059d4df977dece27b8a4a7f9eec942` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-civil-time-20240722.1-r1.apk` | 4864 | `789ed5d3bdc581759cbeddf569736e6626bf0a652b7468434a8d6059a09463ca` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-cord-20240722.1-r1.apk` | 30824 | `7d777f964ec593cbe3389c8d0654c98de61b0182832329f1bbc2749768807815` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-cord-internal-20240722.1-r1.apk` | 18151 | `550c01cc268714ead432bd85e7a446be1b5ee9111e25cd95dcc717667c850594` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-cordz-functions-20240722.1-r1.apk` | 3561 | `6e19173c51a075a5faa51e16c05bb8e9115cfe6fa9210a1e8c0b4d5f8abf0c03` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-cordz-handle-20240722.1-r1.apk` | 5476 | `81eddc0822ee9d853dad41477a3d8818f0fed2dc73c67566d94ff1110cc00390` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-cordz-info-20240722.1-r1.apk` | 6751 | `e6b81a120507d2e8c78673f80a7069b7fca14334afad32371408681a04182111` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-cordz-sample-token-20240722.1-r1.apk` | 3411 | `4b5005fe029134b7bca8bcd4e923f28c983c46b955fbed582e2a7ea6d09fba2e` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-crc-cord-state-20240722.1-r1.apk` | 10958 | `ea616a288b8d4ab6e147847671db818a2c4a4c4ba1f0caba462ebbdb776b413c` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-crc-cpu-detect-20240722.1-r1.apk` | 4775 | `ec832722ca03859f85b1faf47e754553bb136f18232eafa69b4675d7be4b3038` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-crc-internal-20240722.1-r1.apk` | 6871 | `c6540f8fce518ee66eaaae504e5475fbc49f050b5852bfad027ff99b1f0f9ded` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-crc32c-20240722.1-r1.apk` | 5796 | `8d29f8fc86e6d21620d507393cb84a92ef255f7ef491477ec7945b905d6a99b9` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-debugging-internal-20240722.1-r1.apk` | 7704 | `8e0ac9538f99fc32709302e1625f757597b1206fa6d9d2ff828381a0ba86f067` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-demangle-internal-20240722.1-r1.apk` | 16270 | `769947ba041254b17f14304d20d4edef22bceeefb3240729db64cc307a95ec52` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-dev-20240722.1-r1.apk` | 896641 | `8b5410791d6f3500ee664f39f9742e01bd1874671b0a5b3a896eee39bd7dbe73` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-die-if-null-20240722.1-r1.apk` | 3763 | `e2cf633ed9cc0b97a4d48e8141a6a4ab733199edf8b7e2d0febba39887670432` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-examine-stack-20240722.1-r1.apk` | 4341 | `bc8858e8384fe00b89549a622903b0bc61e92bf49c802115a4eefd878cb0932e` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-exception-safety-testing-20240722.1-r1.apk` | 7052 | `4a3b7dd753b654294b793171836077c408bb18f88ec60f287b976375b84ddd74` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-exponential-biased-20240722.1-r1.apk` | 3385 | `a499b0b3b4cbda802389d18bd0212fb8f1af130ea9899a5858e53d84bd174000` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-failure-signal-handler-20240722.1-r1.apk` | 5576 | `2b6b1cc29de02743071677b4d278c6f38b49fbb1ada4193e8462ec0b65c008cf` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-flags-commandlineflag-20240722.1-r1.apk` | 3273 | `af25f3e198057f993dc2ea6542cc304ee21a57f1d46d9748d3378dc6838a333c` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-flags-commandlineflag-internal-20240722.1-r1.apk` | 3245 | `f03008277e3730fd8ab082b2dda36ab99bbc63cf70e7f608ceb9d3eb966d34bc` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-flags-config-20240722.1-r1.apk` | 8293 | `3fd4ffdd257969670f248db6fbb87d2640b96b520859e0ff8a85b54a7ac76fb0` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-flags-internal-20240722.1-r1.apk` | 14301 | `8eadba284b274ad0c60f4b0df9ac5f8397d305439eaf61c9f0c5316aa8a626a6` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-flags-marshalling-20240722.1-r1.apk` | 12313 | `0040c6ee67af7b7d1e19439e167ec56a0410dc239accd575446d8b7f28ce6679` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-flags-parse-20240722.1-r1.apk` | 24110 | `6d50e714a80dd24117a3f1f834afa8ac235699e6db8b8e70ae816f18217857e4` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-flags-private-handle-accessor-20240722.1-r1.apk` | 3405 | `c67a053f2fad1f9da5e1aaf69358227becf6f140d75e9f2450f40214be948399` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-flags-program-name-20240722.1-r1.apk` | 5465 | `0d9d40657fd7e0541b2410bdcea1a10ff4ee4174caaa33e8856e654977fdd371` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-flags-reflection-20240722.1-r1.apk` | 14214 | `49931263c9cc754adba1cab8016322fd103e51795b37af2ff0dfdcc0e789c6b4` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-flags-usage-20240722.1-r1.apk` | 4348 | `3bb0d3f94d6a3855ffbf85abeb5b20ea9af77f50ac120461779821a27f9deeff` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-flags-usage-internal-20240722.1-r1.apk` | 16761 | `7452738c45dc079bfe8e24d30db06b1ff07d9a70ca12e196b54bd7c911ccce12` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-graphcycles-internal-20240722.1-r1.apk` | 9114 | `de9a87e87dae840dceac4d208a4f18298de808da13449e816b924b46bcdc7d13` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-hash-20240722.1-r1.apk` | 4034 | `22a56f9b3f379a8bc637a5d967177f38b8ddaab4802f3c6c93366470f9eb00e8` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-hash-generator-testing-20240722.1-r1.apk` | 6494 | `7a0fa74910b56ac0a2dec6c2f7485994c36952da6dd54e7ffd6bb48c03212c1a` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-hashtablez-sampler-20240722.1-r1.apk` | 6120 | `459f35ba4b16b581b94ea6f58516261c208b2bcdca35a08c32968cba1d8dda00` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-int128-20240722.1-r1.apk` | 7632 | `09d4d144a654a8d3c06c91847f048751c193bf83bce1059e681315a4ed056cfc` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-kernel-timeout-internal-20240722.1-r1.apk` | 4820 | `42b91ed3a63c1a813b3eeab5ac42085f8e237a9300545a152d64ab5dd108d7e4` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-leak-check-20240722.1-r1.apk` | 3127 | `7e8d23d269a5474156aaf64d29db318f9c45ccc71f040e88d3ceb9c9722af4ce` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-log-entry-20240722.1-r1.apk` | 2747 | `dd884c751a9643776f6f91749129ff634ce10ed5390fd1c9c09f28daf62701cb` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-log-flags-20240722.1-r1.apk` | 8607 | `140808a8c128a4aa0e54190513c1e440b73825b1d34ae261b2d5ec83c983c541` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-log-globals-20240722.1-r1.apk` | 6647 | `555cd0cb4291021a4608654f5cfb18e119cabad27f0393a4ca753788ac769e34` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-log-initialize-20240722.1-r1.apk` | 3057 | `b003acf8ab4cf386702049a8761da550a783e433434df933cfb706c5e661c206` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-log-internal-check-op-20240722.1-r1.apk` | 7284 | `840ad5be81214dfed66316dddfafe96b820552144ddfc4624f977031e24420d1` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-log-internal-conditions-20240722.1-r1.apk` | 3414 | `4c3964ae7b77a9098edf205ebec7a3424169ed531b1c60bc1fbf861a96101017` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-log-internal-fnmatch-20240722.1-r1.apk` | 3926 | `380d1ea2a174df5c4ce83c9213f1b513ddcde30baa108bdf43a72d06f2687578` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-log-internal-format-20240722.1-r1.apk` | 5298 | `dfe8c1b65210bae9a574784347deed76a9e2d989040a81b93d69a190b0c8d4a7` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-log-internal-globals-20240722.1-r1.apk` | 3869 | `099e55874103ec8fff09d68740c0db87a4223f2a4ae2f889c5e721c141345391` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-log-internal-log-sink-set-20240722.1-r1.apk` | 6753 | `f83684a7d90a27191f0ccb635b2518a42e351c9f7a3d8b6e2f2b87737ccf5a4e` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-log-internal-message-20240722.1-r1.apk` | 15049 | `a9db609305ea32cab8d45b2aaaf933d4f010f84c385a87c7687c1f6f96d01c47` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-log-internal-nullguard-20240722.1-r1.apk` | 2891 | `41ea4867a9826088f24f98c433e5ac9ddff3d1c835e9319804089392b182ccd8` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-log-internal-proto-20240722.1-r1.apk` | 4285 | `3a6939ed2d31e2dfd1866d58b7145a4c4dd5f985b3cf449c9db766e8a5eacbad` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-log-internal-test-actions-20240722.1-r1.apk` | 4820 | `0589a82c0cb22a967aa893f4411fe9d5147716f1cfc4144701cfdee289a1596b` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-log-internal-test-helpers-20240722.1-r1.apk` | 4008 | `e447e60f48b67a57c27513b581abf091431720e2dbd46360ec81d8b97d84911b` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-log-internal-test-matchers-20240722.1-r1.apk` | 39356 | `c358f823cba27d25b1ca63a0c2cf1240e4cafed9280f3baa184c60a3cd1c22f1` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-log-severity-20240722.1-r1.apk` | 3342 | `9584237f89ceedf9bce1c344437ce0b7678c515b9e880abbc953ccd346277980` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-log-sink-20240722.1-r1.apk` | 3146 | `166aadaa0c25cfb9319c0f4a6fb856e4a5b45afdf0d7114ef35c42d3bb8051df` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-low-level-hash-20240722.1-r1.apk` | 3923 | `b43832d3cfcdc164dd222c12eb4ecd36f545f10779c8e7373524fc54bf65dd41` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-malloc-internal-20240722.1-r1.apk` | 7576 | `01d1e4dc7f6250328e8dd77fcce894556e39ffcd0608985ada30a635d3bd4516` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-per-thread-sem-test-common-20240722.1-r1.apk` | 13664 | `1cf0037b8e2e3d6d0c72f878079793964a7004f035a811a93031540da0c777a7` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-periodic-sampler-20240722.1-r1.apk` | 3462 | `766783935b32c789db24d21be3a911c02ef8779996d86b9a758798017f460e6b` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-pow10-helper-20240722.1-r1.apk` | 8123 | `752a52c58178e978dd3b37612eda6239fadc63e2d58036ffd1959c78ba805539` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-random-distributions-20240722.1-r1.apk` | 7769 | `b2da29ef3286d2c4ba4f330cce8de2cb3cd6c42a3512a67cceba0b84e44b4a51` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-random-internal-distribution-test-util-20240722.1-r1.apk` | 9409 | `f9e98bc5730319ef0ab574b7d92a17f39c733a85c21ae656d8284fd8e327b602` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-random-internal-platform-20240722.1-r1.apk` | 7427 | `1ed18432a4679cca8dd9bfa5f7bc3703423fc3b0faa8b9bf844f84d546da687e` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-random-internal-pool-urbg-20240722.1-r1.apk` | 6057 | `112ffa41865375fae8cf05af9817cb45e4abdcb68a72fcac3d8fb3b8e528467e` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-random-internal-randen-20240722.1-r1.apk` | 3510 | `bf338797d9e5fd74ebf3755ca97ead9e702f23b325a85664af96aabada181ea1` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-random-internal-randen-hwaes-20240722.1-r1.apk` | 2938 | `4f826aab988174130502000f29d853991c08be3cc9ba0e3a845ec3af5b49fac5` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-random-internal-randen-hwaes-impl-20240722.1-r1.apk` | 3596 | `4dcf0a44e5fb1104d6b05dbe5ef05002e935613b01e1f4e313f0468779f07a24` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-random-internal-randen-slow-20240722.1-r1.apk` | 7970 | `65de35f678c05c480848cca096b8dd6931bf4e40b380b92417334c63521702b0` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-random-internal-seed-material-20240722.1-r1.apk` | 3970 | `c6e13af83be3ea7b27ede93188c2b0a1f0fc31fb0cbca3ecd52724c83cd6df3d` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-random-seed-gen-exception-20240722.1-r1.apk` | 3515 | `1906a6bcd7cd16861b75f87083556dfd775a9bed8deef5a921b11497148c855a` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-random-seed-sequences-20240722.1-r1.apk` | 4128 | `4b11c888858bc2b2328d0175da05a7a826ff239cbcc64ada1ffa33b54ee9783f` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-raw-hash-set-20240722.1-r1.apk` | 6211 | `a9ceb44ff2ae091b55742a4190d1107ad39954137442d5efd9ae33d3eba3f898` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-raw-logging-internal-20240722.1-r1.apk` | 4675 | `1078f3d4620720c84002f75fbf4623332d283f9b8787eb89d2531728a53bf3db` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-scoped-mock-log-20240722.1-r1.apk` | 36874 | `5fd05c865ca8d3df6297c95da0b1e4ddceea1f51df86ac30bda6db70cfb2fedc` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-scoped-set-env-20240722.1-r1.apk` | 4522 | `4301b3c085abac7cff2424934c44551377148dafdc22b93f092173ff08441d7e` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-spinlock-test-common-20240722.1-r1.apk` | 17261 | `696966b0645527bcea5392ea51bde53b25640fa45758e225668ee4a11a1629c3` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-spinlock-wait-20240722.1-r1.apk` | 3743 | `375af8ee4052a8e1b9df0815601a0c20df501352ec39aa84d30f339b62dd48bb` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-stack-consumption-20240722.1-r1.apk` | 4240 | `426ab5f8f9564765a488ac242b08ea4a04380bcca646aae34e223b7d62e8b38f` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-stacktrace-20240722.1-r1.apk` | 4216 | `f8c3cfb1984385e31a4bdafa722f5ffa29d53aad645782f597917b5abc852831` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-status-20240722.1-r1.apk` | 14069 | `969ebe574dabd91c3d129bb3788d9dd56072a3bb4ef90aeac35493eaf9b8e32d` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-statusor-20240722.1-r1.apk` | 6626 | `3a27cde47210d6ae503184666a38b1a88901920deff8b1f2bdcac57a48db7a70` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-str-format-internal-20240722.1-r1.apk` | 31765 | `813846b642e482329615094945d0807632cedd25f6fc253f9d46c67b17de1f65` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-strerror-20240722.1-r1.apk` | 4253 | `dba4aa1734db6a3fe192440a1a457b6aea7c1cf32e49598dd300d971c041826b` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-string-view-20240722.1-r1.apk` | 2749 | `493f1c1b69e5695508e9745ce6c73116f19304a50fb56ecc6753d7e7dc5c4cdc` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-strings-20240722.1-r1.apk` | 50082 | `6bf657d59fc58d4fded59e6c08986349013aee2b2c42eac7ae962a0ba8183bf7` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-strings-internal-20240722.1-r1.apk` | 6567 | `1dd098301d2c8b1616e42e1a32293c1cbb8e24aaa639d1d676babf00af7d3582` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-symbolize-20240722.1-r1.apk` | 3172 | `8513632482352d66f4e76f3b46069d581ff1fdbb20348b2a37630daa97173bf7` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-synchronization-20240722.1-r1.apk` | 20297 | `04ff97ca4e4bd0515a0f1de2e96318841790bca8274705bf36f3a4837bb6ab56` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-test-instance-tracker-20240722.1-r1.apk` | 2969 | `32629fac275077357d7a293ea3fb7d823826237154616e3de0929a8061c74a6a` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-throw-delegate-20240722.1-r1.apk` | 5127 | `572b8a29b16d7f046963dd5984c7b770ab008f2e0d5a7a2ea76befb328816872` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-time-20240722.1-r1.apk` | 25501 | `ba7da772763a0279e9a2d7ab78f2de93f9b5ebf13b33cbf78bc996ee8026ebfa` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-time-internal-test-util-20240722.1-r1.apk` | 4195 | `b8397f0cb0e7ef7fa54e3f0ea6407bb07fd6431c193acb52ecbd7702b442c990` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-time-zone-20240722.1-r1.apk` | 38831 | `cf58c7f1e1cd06f13f7f6ca9ec1e3dcc94896e61785c5254681d4727c750a0c6` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `abseil-cpp-vlog-config-internal-20240722.1-r1.apk` | 10382 | `dcebd01aff845190282e431e004b4460ed273625c406f60f95a9305a70dbdba2` | abseil-cpp | `e706802dc523d4283241bd6ff6f5435a181edea0` | Apache-2.0 |
| `acl-libs-2.3.2-r1.apk` | 14379 | `83c35935dcc0d592f65bc4626cec243b2c5f1a0a3d3e1361f10c4bb221a941f1` | acl | `8bac74716d06c84627ab02d101fd9d2bafd0a34c` | LGPL-2.1-or-later AND GPL-2.0-or-later |
| `agetty-2.41.6-r1.apk` | 20394 | `7d7d5f67cdb301a82be2f4a051f98f5a3a5c91877d28188d3df011af3143b049` | util-linux | `b91fb14e28957c6f5a13c02eb9ec136c82ebd50e` | Public-Domain |
| `bash-5.2.37-r0.apk` | 447041 | `8218982214f1b51f520d282b0c81d654846e974ce009e758acc6187bd64fe228` | bash | `dfdce3cefb431614e410ac9bc3665d33ea45020c` | GPL-3.0-or-later |
| `blkid-2.41.6-r1.apk` | 19460 | `ed337342191188f6846db11d76aeb485c62cf0281867e82c194d66b0295536fc` | util-linux | `b91fb14e28957c6f5a13c02eb9ec136c82ebd50e` | LGPL-1.0-only |
| `brotli-libs-1.1.0-r2.apk` | 414597 | `a693524543421b3a90f163ccb48d5ad0f5fd773b5c3b640acc461eace2cb01b6` | brotli | `9c7716c2221405ce7810ba3eaaa1f62d2e646c20` | MIT |
| `build-base-0.5-r3.apk` | 1306 | `2788ae90dc82999b26d121536ec2bd1c053e46b470c0202229bd4b4d2347d1b4` | build-base | `2d1f9f414de2521837a7a9c7068217b76e3452ca` | MIT |
| `c-ares-1.34.8-r0.apk` | 109507 | `1397ec9682ff6153e5d037965c76408e570ae6535ce479cc2af37436fdea52ce` | c-ares | `3366070614dbbf4e22a9e560c90eeb934752a2cd` | MIT |
| `ca-certificates-20260611-r0.apk` | 129495 | `a8ad8f04dfba1a2897388c4b420b698bf1ecd870be10f0127134a567d5e59896` | ca-certificates | `5b10c3f23f6d4e588859db153f0949c850d7f8aa` | MPL-2.0 AND MIT |
| `cfdisk-2.41.6-r1.apk` | 31870 | `0a49532d04bfbedfa94146df6b8c8a56920aa884b4345e43478e9a3866c30b8b` | util-linux | `b91fb14e28957c6f5a13c02eb9ec136c82ebd50e` | GPL-2.0-or-later |
| `cmake-3.31.7-r1.apk` | 21663548 | `3f99fc6bb19b8e41f33764bf641bb181d57bdd1afb63f2dfee8d4547e1362341` | cmake | `be0833caee3020f089f02c5d7223e971a9a11ffb` | BSD-3-Clause |
| `coreutils-9.7-r1.apk` | 525158 | `f560dcf395e376abbfaf8fccd913d7260100975818c6cb9094832c13c75321c8` | coreutils | `2abbae31ddb4265cfa2a71e0a8fe12edde904cf2` | GPL-3.0-or-later |
| `coreutils-env-9.7-r1.apk` | 17544 | `d1f0969fc5446ec74042600e4ed36c61a7bcb5750b391e1c78143afc90a8e4ad` | coreutils | `2abbae31ddb4265cfa2a71e0a8fe12edde904cf2` | GPL-3.0-or-later |
| `coreutils-fmt-9.7-r1.apk` | 15380 | `e50150bef53ac1a6adade0647cd59b3064f3b0cc6e49307591b6f8af2507c359` | coreutils | `2abbae31ddb4265cfa2a71e0a8fe12edde904cf2` | GPL-3.0-or-later |
| `coreutils-sha512sum-9.7-r1.apk` | 15356 | `e42e5ffdf14f4b27cfc29538b367489c06533c2eaa451151d0140016d5d08438` | coreutils | `2abbae31ddb4265cfa2a71e0a8fe12edde904cf2` | GPL-3.0-or-later |
| `curl-8.14.1-r3.apk` | 165890 | `ec89d3e01d2507e0ece31746018f0c053a4fbd007628dc3016afab406b5c0ff6` | curl | `60fa9cebe718c0c5b9b6b2ae809f887dc344f0d0` | curl |
| `dmesg-2.41.6-r1.apk` | 23271 | `0eeb5400a137c26d5f1686503f2fd451ff25acf6e915237187ae588294acf358` | util-linux | `b91fb14e28957c6f5a13c02eb9ec136c82ebd50e` | GPL-3.0-or-later AND GPL-2.0-or-later AND GPL-2.0-only AND GPL-1.0-only AND LGPL-2.1-or-later AND BSD-1-Clause AND BSD-3-Clause AND BSD-4-Clause-UC AND MIT AND Public-Domain |
| `file-5.46-r2.apk` | 9729 | `94c99dfe7cde72e07aa2b289674e682e821518bfc59e31ce628990d939caed7c` | file | `bd570c2a8fc5988357b1415c93c0c69b3f4c8996` | BSD-2-Clause |
| `findmnt-2.41.6-r1.apk` | 24065 | `bdc0b8edb78f13c88505513f23c0209b4b34d65323aca5a7dad9a070d0d4cd15` | util-linux | `b91fb14e28957c6f5a13c02eb9ec136c82ebd50e` | GPL-2.0-or-later |
| `flock-2.41.6-r1.apk` | 7075 | `e026be3775d3fd56f594f4244565babe39aaf24f7331644c6ea6bddb9539c36f` | util-linux | `b91fb14e28957c6f5a13c02eb9ec136c82ebd50e` | MIT |
| `fortify-headers-1.1-r5.apk` | 6814 | `544a27bd0e002f54677109e2cce594f10f7d0df5321e5e64604e896bba92cdf8` | fortify-headers | `175895ac5c1d9d62add7fe3c5a7f39548b8fd715` | 0BSD |
| `fstrim-2.41.6-r1.apk` | 13326 | `8b584cf559805f41c2ed76509b513f68e3fff2fa8594d87b2cdc6fde42115d94` | util-linux | `b91fb14e28957c6f5a13c02eb9ec136c82ebd50e` | GPL-2.0-or-later |
| `g++-14.2.0-r6.apk` | 16683602 | `4490ba28b819efdb26a78493e63942605a022d407652eea77027eaba918e6f1a` | gcc | `fbf60319be3bbaf6dd32ef55cc6fb7189e05c266` | GPL-2.0-or-later AND LGPL-2.1-or-later |
| `gdbm-1.24-r0.apk` | 31061 | `cb524a457ffbd9c79c6711d9ee883a64a5a9bc6aec4f4b4d047ee67527ac6e6d` | gdbm | `cf76e1b436494c60e0c188400007dbf78bbff5f0` | GPL-3.0-or-later |
| `git-2.49.1-r0.apk` | 3411448 | `42f4573799ffce0c7dd4954d2247eb882eb87360dc18637930624484ecfd1c90` | git | `d896b70b77339c50bea678a19895df6331872d82` | GPL-2.0-only |
| `git-init-template-2.49.1-r0.apk` | 10365 | `b8d9dc864aa8c68e93d1cc80d069d56f1ebbed9e8bd90a5fd9a6f2d183258fcc` | git | `d896b70b77339c50bea678a19895df6331872d82` | GPL-2.0-only |
| `git-perl-2.49.1-r0.apk` | 15323 | `ad5c2432d032a89825626101aab85ed2ea226c78e66633053d3097d67f3b72a8` | git | `d896b70b77339c50bea678a19895df6331872d82` | GPL-2.0-only |
| `gmock-1.16.0-r0.apk` | 35903 | `827a2132c63b70ede1c60afb026664ef61207f10557b9fb6874111d1bc379989` | gtest | `e462aca576b9c6016fcfda268366141036020eca` | BSD-3-Clause |
| `gtest-1.16.0-r0.apk` | 145356 | `6b4be9f161eadf0681b34182ecdc153b445503945f8889548dfd57d6ba8b97e7` | gtest | `e462aca576b9c6016fcfda268366141036020eca` | BSD-3-Clause |
| `hexdump-2.41.6-r1.apk` | 16490 | `ef5ecea8a7e59d4be5de70c2103a444f09fac43f64e1acea175cbc84c0006cc7` | util-linux | `b91fb14e28957c6f5a13c02eb9ec136c82ebd50e` | BSD-4-Clause-UC |
| `jq-1.8.2-r0.apk` | 155653 | `dc73a46f8a2b0827fb6b0590f07d8f456a41f3fae44e34fe7e3a09b4329325e3` | jq | `cda909a29acb0a49ec6666ddb546b3e04b89effa` | MIT |
| `libarchive-3.8.3-r0.apk` | 320868 | `229e3881cbbe148413fd1d04bce78749ec6fe4f36a4c413a8062b7c854c694ce` | libarchive | `dba36b915eabc9de74a587c9c83f0902f998a7b5` | BSD-2-Clause AND BSD-3-Clause AND Public-Domain |
| `libattr-2.5.2-r2.apk` | 7987 | `1e2331a0e828bd5c61dd45b321ae2b88b9eceae5732100fd95270fe9981bff21` | attr | `40760f1909b662e8b9065217452a1782bad3dab1` | LGPL-2.1-or-later |
| `libblkid-2.41.6-r1.apk` | 95287 | `ab85cd837c906979c24e5a006a81789ae9715e6e913c421c71950bdf1450164c` | util-linux | `b91fb14e28957c6f5a13c02eb9ec136c82ebd50e` | LGPL-2.1-or-later |
| `libbz2-1.0.8-r6.apk` | 32847 | `0c98810f9332bf1bb1b0acc64eaac4b101036689bffba9ea621416b4b3c190cd` | bzip2 | `33283848034c9885d984c8e8697c645c57324938` | bzip2-1.0.6 |
| `libcap-ng-0.8.5-r0.apk` | 11420 | `a02e227d96cf83627a8dd1561e12d89962fcb659bbba437d6b6a0b96dba6dfa4` | libcap-ng | `eca5824ffb9bd4158a839862d2e760724bf38b37` | GPL-2.0-or-later AND LGPL-2.1-or-later |
| `libcrypto3-3.5.9-r0.apk` | 1986879 | `3f5825ced5fde1c66a5376a3f6076b3c08538ad52d9ef23f069857e212d9175a` | openssl | `b6d0d5c5639c0034e9073c39e9ff139e28e71818` | Apache-2.0 |
| `libcurl-8.14.1-r3.apk` | 330915 | `249e5a3a50558cdb3ce1bab1619b15d88243a628d878700c8d05878c2e71ed71` | curl | `60fa9cebe718c0c5b9b6b2ae809f887dc344f0d0` | curl |
| `libeconf-0.6.3-r0.apk` | 24446 | `fe4fbf324f84f7c8b475cfc708c5505aa630bced7b5f6289bf5ca36d9b587829` | libeconf | `1e0aa723fba50417893fe5f6cf72f76d044b8192` | MIT |
| `libexpat-2.8.5-r0.apk` | 61426 | `771c18e6f7891a503a4664cfc09a3c4fb35a9b2fd2d4a643caf7206b792f5444` | expat | `4ffd5cf4f348fb2b9c0200fc2a815d5e3904e8e2` | MIT |
| `libfdisk-2.41.6-r1.apk` | 125688 | `982da3f5a67acb1172693b82b6587ceba34c73b9c8669f86730b26a40166ab0b` | util-linux | `b91fb14e28957c6f5a13c02eb9ec136c82ebd50e` | LGPL-2.1-or-later |
| `libffi-3.4.8-r0.apk` | 18222 | `9a75cb9024693c1e52c3d8d7c9afb7c79e6e20f6c08df28effdb8dd816095083` | libffi | `be5e49159a2ccca93a3290af3d8ab25443523363` | MIT |
| `libidn2-2.3.7-r0.apk` | 104435 | `515cfe061176c7456ea3548651d0014084d77dd3774b78e2c944404ae75a41ff` | libidn2 | `1cdcdd0eccbee1f60078417a7aaf83f92f6e6754` | GPL-2.0-or-later OR LGPL-3.0-or-later |
| `libmagic-5.46-r2.apk` | 512571 | `1fe23639567b42d215d860b2983ed4ccad442c658fbc9082e946823e87c251a8` | file | `bd570c2a8fc5988357b1415c93c0c69b3f4c8996` | BSD-2-Clause |
| `libmount-2.41.6-r1.apk` | 128334 | `722dfd3d977054b9b9af218ba89f980630e07d21122299a98dbcf617fdc3d015` | util-linux | `b91fb14e28957c6f5a13c02eb9ec136c82ebd50e` | LGPL-2.1-or-later |
| `libncursesw-6.5_p20250503-r0.apk` | 159016 | `aeafdfca68147b014705b4e2564639ade6345198debb522f2c6c51d32e417651` | ncurses | `3fefbe8dda8b3e85458edb190e2f3a69ad16035c` | X11 |
| `libpanelw-6.5_p20250503-r0.apk` | 5651 | `046257a4535a9ced124595a33053948f6bf8b2f02988fefd1108f514d213ad4b` | ncurses | `3fefbe8dda8b3e85458edb190e2f3a69ad16035c` | X11 |
| `libprotobuf-29.4-r0.apk` | 1147107 | `b836fe3164b55767ced71aa19916eea1b2b2c8be3eff1f8c224852ad450487e6` | protobuf | `5eaa1e1bfc982d5518c66df077252b5a72ffec60` | BSD-3-Clause |
| `libprotobuf-lite-29.4-r0.apk` | 217038 | `af0e26ab830c28e309e2fdf7001fcba24e4d2b9d51bf936f18e3e4efa3489176` | protobuf | `5eaa1e1bfc982d5518c66df077252b5a72ffec60` | BSD-3-Clause |
| `libprotoc-29.4-r0.apk` | 1298366 | `9e3606fafad6a22a2d45b1f07794935e1161452111dfd1ac3e247bb1e79157ae` | protobuf | `5eaa1e1bfc982d5518c66df077252b5a72ffec60` | BSD-3-Clause |
| `libpsl-0.21.5-r3.apk` | 54710 | `1e79da4fa1364b7153b8950a363a6de0bef1d1b48d46fcb3b850cd4f233727b2` | libpsl | `4cf07ce428e77d8bca8e45258ba1937db8b18661` | MIT |
| `libsmartcols-2.41.6-r1.apk` | 55341 | `44ae64575336e2582b5101676f754355afeebace2b406a40419075798b58b3e0` | util-linux | `b91fb14e28957c6f5a13c02eb9ec136c82ebd50e` | LGPL-2.1-or-later |
| `libssl3-3.5.9-r0.apk` | 383680 | `6801c740b9760b5b08da8db6367ebc18b2cc4dbaf371f7148429538b8bb04e23` | openssl | `b6d0d5c5639c0034e9073c39e9ff139e28e71818` | Apache-2.0 |
| `libstdc++-dev-14.2.0-r6.apk` | 3985717 | `13e2169b46a24f03c87caf91387312724b01951c222bd061d6d87c48903836a9` | gcc | `fbf60319be3bbaf6dd32ef55cc6fb7189e05c266` | GPL-2.0-or-later AND LGPL-2.1-or-later |
| `libunistring-1.3-r0.apk` | 733791 | `989640e58f7646c0495c3950df36eb7b4df152d8150c2c888f8ab954fed8c908` | libunistring | `22200a467cea998010743cc288889dbde0496d4a` | GPL-2.0-or-later OR LGPL-3.0-or-later |
| `libuuid-2.41.6-r1.apk` | 14359 | `eb8fa9e042b51443a6ac8c9fa4d1dca5a1a458c5f3980bffa5167f005f47a504` | util-linux | `b91fb14e28957c6f5a13c02eb9ec136c82ebd50e` | BSD-3-Clause |
| `libuv-1.51.0-r0.apk` | 98184 | `6cd879561ba6380c5664c221c0de33af177becb0d94a5de0d5d90589a2089737` | libuv | `0a3c27d7a1c6d7c04e9ab76a55d96e3bf1ab44d2` | MIT |
| `linux-headers-6.14.2-r0.apk` | 1682182 | `b0d7184f0e8d926961b82dff3d8a6a1f85db100dfc97e3fa1e6a25bbe9fd0f71` | linux-headers | `7aeec83f1c6bf21c453a05debb215f927eaf5dd2` | GPL-2.0-only |
| `linux-pam-1.7.0-r4.apk` | 199873 | `0152e9cd1d13986b75e4ccec8155a878791083ddca7e2667bbbb398bc62c9703` | linux-pam | `072d73e00ef00a23919c2a7620056670b04cda2a` | BSD-3-Clause |
| `logger-2.41.6-r1.apk` | 13015 | `f86e00031e0ff783dd583d032c85ddaa4d3fc57ec908dce0e3f1cb3adb96f8d1` | util-linux | `b91fb14e28957c6f5a13c02eb9ec136c82ebd50e` | BSD-4-Clause-UC |
| `losetup-2.41.6-r1.apk` | 26032 | `3472103e45cfcbbc5748b40ec203fe5b0c9ee64226b533311ec47e6c3fee089e` | util-linux | `b91fb14e28957c6f5a13c02eb9ec136c82ebd50e` | GPL-2.0-or-later |
| `lsblk-2.41.6-r1.apk` | 54885 | `f647ce245c36ee6b4ed351404c9f75f7702e9239949b24863a786f0d08ae372a` | util-linux | `b91fb14e28957c6f5a13c02eb9ec136c82ebd50e` | GPL-2.0-or-later |
| `lscpu-2.41.6-r1.apk` | 39917 | `c71e757c82158e6896d0222e1dcf0e4afe37067eec8b3971f9762e68329c3a0d` | util-linux | `b91fb14e28957c6f5a13c02eb9ec136c82ebd50e` | GPL-2.0-or-later |
| `lz4-libs-1.10.0-r0.apk` | 70678 | `b4f393b9d8ce5a431788b31c899734f84d60a47487a6b833ee8d8012c501fe3f` | lz4 | `a886e2e46171e6d5991dc91c492ae748a83b40e4` | BSD-2-Clause AND GPL-2.0-or-later |
| `make-4.4.1-r3.apk` | 117754 | `5b66eb4c2db0b0452f1c88d19909397f09e72425d1d9769a480d6370d8a9c310` | make | `be0833caee3020f089f02c5d7223e971a9a11ffb` | GPL-3.0-or-later |
| `mcookie-2.41.6-r1.apk` | 8569 | `406552151236dd280b778ca6af3ce6ae646bad763bed7e2b17665d527da94aa9` | util-linux | `b91fb14e28957c6f5a13c02eb9ec136c82ebd50e` | Public-Domain |
| `mount-2.41.6-r1.apk` | 14399 | `fb3818e033d077ccec395d8e8df0a73a05eeb6ada3913bc0c48e64ca5393dc44` | util-linux | `b91fb14e28957c6f5a13c02eb9ec136c82ebd50e` | GPL-3.0-or-later AND GPL-2.0-or-later AND GPL-2.0-only AND GPL-1.0-only AND LGPL-2.1-or-later AND BSD-1-Clause AND BSD-3-Clause AND BSD-4-Clause-UC AND MIT AND Public-Domain |
| `mpdecimal-4.0.1-r0.apk` | 79004 | `28f3d868efbc1e9093b95f4a3f6e74393acd4a37292fcb5c0e0e0612fe83fff3` | mpdecimal | `c0519b85456e9b838e3142e1d233aab0b433b476` | BSD-2-Clause |
| `ncurses-terminfo-base-6.5_p20250503-r0.apk` | 21767 | `0815a5f0403974bb9c34d456e71dc9c0222cb5455d393bc63c44b573da3d7fe0` | ncurses | `3fefbe8dda8b3e85458edb190e2f3a69ad16035c` | X11 |
| `nghttp2-libs-1.69.0-r0.apk` | 63198 | `d6ee515d30d703e94b55ef9c0a02aea053313f654acbd2c655d18e3907ecb66a` | nghttp2 | `87de39802b2c34c9a7c62a52b3e39e05af1c974e` | MIT |
| `oniguruma-6.9.10-r0.apk` | 187777 | `52f7f6f99840f252d611ded9d72c8ecfdc99888391d6cbc33a7ba6703c271dfe` | oniguruma | `31082e89063dfb6b02af0b38c46af803a118137a` | BSD-2-Clause |
| `openssl-dev-3.5.9-r0.apk` | 366018 | `86cbdf7fbbef81ba79ee238b90a56bfde6d02a70fe71c00a7de05872b9f5d9c4` | openssl | `b6d0d5c5639c0034e9073c39e9ff139e28e71818` | Apache-2.0 |
| `partx-2.41.6-r1.apk` | 21852 | `6565abce5aea8e93af22523247a553a77b3ba917fe68bb92fce6d0d6348410b4` | util-linux | `b91fb14e28957c6f5a13c02eb9ec136c82ebd50e` | GPL-2.0-or-later |
| `patch-2.8-r0.apk` | 70567 | `f34098dde672a06d7b601c12d2e585bbf473292dd08d7e0a81e9ad27962196a6` | patch | `094514d20ffc2b3cd1b7eca3fc27744b87df57dd` | GPL-3.0-or-later |
| `pcre2-10.46-r0.apk` | 314267 | `cfb8ad103a101fa6a31769e50e188dab9c60124705682d01b3de268795db58ad` | pcre2 | `a22c8c27a78e00ea7cf03e09c6033a6336ee22a2` | BSD-3-Clause |
| `perl-5.40.4-r0.apk` | 9712465 | `bb6e25b2a8f34852a90ebd066e99e21722486add8272eb3d625783baec9f0654` | perl | `3dc7e75dc15209dcdf940bea52ec094d29e0ad73` | Artistic-1.0-Perl OR GPL-1.0-or-later |
| `perl-error-0.17030-r0.apk` | 11920 | `20ccae12b78d6cda5836b92f85fa36f32ad70bb4bdf62478b5f87f8ae5bed165` | perl-error | `08d5900de41ce5b269b4bd695a217c4d2bca2ed3` | GPL-1.0-or-later OR Artistic-1.0-Perl |
| `perl-git-2.49.1-r0.apk` | 33016 | `c00689c101a8957056f53de6bbd162ecb58962b64374681ce3d7d206b4ad4ac3` | git | `d896b70b77339c50bea678a19895df6331872d82` | GPL-2.0-only |
| `pkgconf-2.4.3-r0.apk` | 52480 | `32ed811fa76f5f380cda11aa5bdf2f93727760dc4c6d6de5f06dd4c66e3fe3ba` | pkgconf | `5be535df8a0565ca60a69a44601937d4288e353c` | ISC |
| `protobuf-29.4-r0.apk` | 4422 | `c578e2bc51a8004e1c3a833027014513615089221d031a991f5e1795bfab5de3` | protobuf | `5eaa1e1bfc982d5518c66df077252b5a72ffec60` | BSD-3-Clause |
| `protobuf-dev-29.4-r0.apk` | 2653204 | `555b65b52b68782678e985d0d5f8b55c4f4c706fdaaff6995b2e2ea4c2ac1550` | protobuf | `5eaa1e1bfc982d5518c66df077252b5a72ffec60` | BSD-3-Clause |
| `protoc-29.4-r0.apk` | 312018 | `5952b34bdaf52279781e6b2f78d8745ab3f053c81dbe8dd14f9bbc8d11660f5e` | protobuf | `5eaa1e1bfc982d5518c66df077252b5a72ffec60` | BSD-3-Clause |
| `pyc-3.12.15-r0.apk` | 1270 | `8eb1af82a5595a924a49add046e8649c27d4a0d71fd7ad49fe78b9a83e3b3488` | python3 | `18ae07d47fb83eecf3343ba1d41fddb4b70b116d` | PSF-2.0 |
| `python3-3.12.15-r0.apk` | 8078995 | `65abdc4bef40a80beb0cad8238c984937d334cfcdd2719651fe7c3a3f6c909e8` | python3 | `18ae07d47fb83eecf3343ba1d41fddb4b70b116d` | PSF-2.0 |
| `python3-pyc-3.12.15-r0.apk` | 1317 | `3f2e74606feb05c51746d60aa5390318d985eb827e93709142c287751f4f8d1c` | python3 | `18ae07d47fb83eecf3343ba1d41fddb4b70b116d` | PSF-2.0 |
| `python3-pycache-pyc0-3.12.15-r0.apk` | 4180913 | `b30c41e6b84bcd2ef16a687dec7ec5ead85ab0a5061cf5e4e5924bf5d55bc78d` | python3 | `18ae07d47fb83eecf3343ba1d41fddb4b70b116d` | PSF-2.0 |
| `readline-8.2.13-r1.apk` | 120574 | `520fa586c689144928191bee13e2c85ff4e170ad87d1471ec48e3e97611673d8` | readline | `be0833caee3020f089f02c5d7223e971a9a11ffb` | GPL-3.0-or-later |
| `rhash-libs-1.4.5-r0.apk` | 138423 | `c48bd5cf228e606e961f07a67bf08cfae60136cf93f86f5005678ea7b374bfb9` | rhash | `86f1a467115dbaf5c05a6683aaf6b66c2c5cad80` | 0BSD |
| `runuser-2.41.6-r1.apk` | 20189 | `5e7dd1e2b1f2f7d828e2a1e02af32c8828730da2580c94063c54e10ca2f4ee2a` | util-linux | `b91fb14e28957c6f5a13c02eb9ec136c82ebd50e` | GPL-2.0-or-later |
| `setarch-2.41.6-r1.apk` | 7804 | `25c44788e4f24197fa1932544b9ba0f0e7c73d3f518608c6da0a261f53a67755` | util-linux | `b91fb14e28957c6f5a13c02eb9ec136c82ebd50e` | GPL-3.0-or-later AND GPL-2.0-or-later AND GPL-2.0-only AND GPL-1.0-only AND LGPL-2.1-or-later AND BSD-1-Clause AND BSD-3-Clause AND BSD-4-Clause-UC AND MIT AND Public-Domain |
| `setpriv-2.41.6-r1.apk` | 13965 | `2be706f74268fc1841bb76d6b333c5db15f139a40eeec7ca5b94fa5517ab2dc6` | util-linux | `b91fb14e28957c6f5a13c02eb9ec136c82ebd50e` | GPL-2.0-or-later |
| `sfdisk-2.41.6-r1.apk` | 34631 | `bb7dfd9750d4cf7cc68a9465c48ae673914bbf64c3648e63cfc0028343eda7a5` | util-linux | `b91fb14e28957c6f5a13c02eb9ec136c82ebd50e` | GPL-1.0-or-later |
| `skalibs-libs-2.14.4.0-r0.apk` | 78874 | `b00cb52d7c9c1309b2c2a11b654162ebabd728cf61898326aeffb39f2a27240a` | skalibs | `b9c5072464571b09666b65869410ee3d40d2ebb2` | ISC |
| `sqlite-libs-3.49.2-r1.apk` | 843561 | `7af9a58595642de91ea35d3d070cd38d969680a720ce76b14966859e6fb4af99` | sqlite | `dac9cea7503a4e9b84d647aab2492d733ac4ac8c` | blessing |
| `umount-2.41.6-r1.apk` | 10976 | `d629aac1169f729a88cfc43f100c501e1f922aa0cabc3be4c95d613c4bc2207f` | util-linux | `b91fb14e28957c6f5a13c02eb9ec136c82ebd50e` | GPL-3.0-or-later AND GPL-2.0-or-later AND GPL-2.0-only AND GPL-1.0-only AND LGPL-2.1-or-later AND BSD-1-Clause AND BSD-3-Clause AND BSD-4-Clause-UC AND MIT AND Public-Domain |
| `util-linux-2.41.6-r1.apk` | 1533 | `c2f2875ecc5365e0d40c01a2784577fd3c96692b521ab5ef8e4274f67d2d402f` | util-linux | `b91fb14e28957c6f5a13c02eb9ec136c82ebd50e` | GPL-3.0-or-later AND GPL-2.0-or-later AND GPL-2.0-only AND GPL-1.0-only AND LGPL-2.1-or-later AND BSD-1-Clause AND BSD-3-Clause AND BSD-4-Clause-UC AND MIT AND Public-Domain |
| `util-linux-misc-2.41.6-r1.apk` | 686498 | `cda88785d425846134ee5ebd7b13b74c26383987be76e1d8bda956efe1bb48ca` | util-linux | `b91fb14e28957c6f5a13c02eb9ec136c82ebd50e` | GPL-3.0-or-later AND GPL-2.0-or-later AND GPL-2.0-only AND GPL-1.0-only AND LGPL-2.1-or-later AND BSD-1-Clause AND BSD-3-Clause AND BSD-4-Clause-UC AND MIT AND Public-Domain |
| `utmps-libs-0.1.3.1-r0.apk` | 5239 | `3d1b9714c720828355c2b231fa188791f2b3e5dc26999681765d5adbbf951989` | utmps | `b8ca1510561d9fa9594fd4e3b5223d7749e6da0a` | ISC |
| `uuidgen-2.41.6-r1.apk` | 6138 | `eeb3f8857ddd0a3522e14b51ec1847101552be82d1a47c52590336c782033723` | util-linux | `b91fb14e28957c6f5a13c02eb9ec136c82ebd50e` | GPL-1.0-only |
| `wipefs-2.41.6-r1.apk` | 11844 | `a2dc2b4306d3017bdce9e7530a833017600fe040672eae28bb56dcc129c5aae3` | util-linux | `b91fb14e28957c6f5a13c02eb9ec136c82ebd50e` | GPL-2.0-or-later |
| `xz-libs-5.8.4-r0.apk` | 118297 | `37e169b7b400304fa7027cab79f9c1c7a280e83acf6c95463384b8abb7ebb254` | xz | `4ad8da6dc8e2b7ed46653b9844835babc3a166ae` | GPL-2.0-or-later AND 0BSD AND Public-Domain AND LGPL-2.1-or-later |
| `zlib-1.3.2-r1.apk` | 55457 | `af24e502645e2b392cae833856d776691ac21655362e5db69d7b89f147f76216` | zlib | `121fc97db0e7c59db704891b6d7ef83ae5df2cc2` | Zlib |
| `zlib-dev-1.3.2-r1.apk` | 34439 | `606473e68819d075f9d3177aabe6f85459397e9659ee8b69fa7d9e42cf4b8929` | zlib | `121fc97db0e7c59db704891b6d7ef83ae5df2cc2` | Zlib |
