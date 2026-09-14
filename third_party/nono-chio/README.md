# nono-chio

`nono-chio` is Chio's narrow Linux adapter around the pinned `nono` 0.53.0
capability model. It exists because upstream `nono::CapabilitySet::new()`
starts with network access allowed and upstream 0.53.0 reopens filesystem
paths when constructing Landlock rules.

The adapter changes those semantics for Chio:

- construction immediately changes the upstream capability set to network
  blocked;
- filesystem rules take caller-owned `BorrowedFd` values and never reopen a
  pathname;
- directory listing can be granted without granting file reads to the whole
  subtree;
- filesystem and network are installed as separate hard-requirement Landlock
  layers so their actual `RulesetStatus` values remain independently visible;
- only `FullyEnforced` is returned as success;
- Landlock ABI 4 is the minimum because network connect and bind mediation are
  mandatory even when the policy grants no TCP port;
- every filesystem and network right known to the detected ABI is handled, so
  later kernel rights are not silently left outside the deny-all rulesets.

The calling process retains ownership of every descriptor. This crate neither
closes nor duplicates a supplied descriptor.

Upstream source and patch provenance are recorded in
`third_party/provenance/linux-enforcement-stack.toml`. The local change
inventory is in `PATCHES.md`.
