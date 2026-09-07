# Chio nono adapter patch inventory

Upstream package: `nono` 0.53.0

Upstream repository: <https://github.com/always-further/nono>

Upstream commit: `c4b25b827330640cb95f85809d88d977191b42e7`

The upstream package is consumed unchanged from crates.io. This directory is a
reviewable wrapper patch, permitted by the enterprise hardening design, that
changes the integration semantics without copying the upstream source tree.

1. `CapabilitySet::new()` constructs upstream `nono::CapabilitySet` and calls
   `block_network()` before it can be returned.
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
