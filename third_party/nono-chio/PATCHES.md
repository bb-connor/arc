# Chio nono adapter patch inventory

Upstream package: `nono` 0.53.0

Upstream repository: <https://github.com/always-further/nono>

Upstream commit: `c4b25b827330640cb95f85809d88d977191b42e7`

Patch version: `0.53.0-chio.3`.

The wrapper carries the reviewed ABI probe from
`third_party/nono-upstream-chio/src/sandbox/linux/abi.rs` in `src/abi.rs`.
The descending ABI order, hard-requirement access/scope checks, and successful
result cache are unchanged. Error projection uses the wrapper's `AbiProbe`
variant; logging is omitted. The vendored upstream tree remains a hashed source
reference for this extraction. It is not selected by the runtime dependency graph.

1. `CapabilitySet::new()` creates an empty descriptor grant set. The unused
   upstream capability container and dependency are removed. There is no network
   allow operation; `enforce_network_blocked` still installs the independent
   deny-all TCP layer. `filesystem_access` consumes the same `PathAccess` directly
   instead of translating it through upstream `AccessMode`.
2. `CapabilitySet::add_path_fd()` accepts `BorrowedFd`, so Landlock
   `PathBeneath` rules use the descriptor already retained and authenticated by
   Chio. No pathname is accepted by this API.
3. Filesystem and TCP network restrictions are installed as independent
   hard-requirement Landlock layers. The two kernel-returned `RulesetStatus`
   values are exposed separately.
4. ABI below 4, `PartiallyEnforced`, `NotEnforced`, or missing
   `no_new_privs` is an error.
5. Both rulesets handle every filesystem and network access right known to the
   detected kernel ABI. Rights added after ABI 4 therefore remain denied unless
   the Chio plan grants them explicitly.
6. `PathAccess::ReadDirectory` grants `ReadDir` without `ReadFile`. Chio can
   authorize directory enumeration while granting file reads only to the exact
   descendant descriptors retained during admission.

The adapter is Apache-2.0. Upstream nono is Copyright Luke Hinds and licensed
Apache-2.0. The underlying `landlock` crate is Apache-2.0 OR MIT.
