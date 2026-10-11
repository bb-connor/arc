# seccompiler 0.5.0 length truncation and selected repair

Reviewed September 16, 2026 by the executing Codex agent. Confidence is high
in the reproduced defect and the checked conversion. This is direct source
review and local validation, not independent human certification.

## Provenance and finding

The selected registry archive SHA-256 is
`a4ae55de56877481d112a559bbc12667635fdaf5e005712fd4e2b2fa50ffc884`.
It corresponds to rust-vmm/seccompiler commit
`c3cf77d65815037931ae5bc2fca010713defdc8c`. The complete production source,
manifest, tests, unsafe boundaries and kernel ABI structures were reviewed.

The public installation APIs accept an arbitrary `BpfProgramRef`. The registry
release converts its `usize` length to `sock_fprog.len` with `as u16`. A program
with 65,537 instructions is therefore presented to the kernel as a valid
one-instruction program. Both `apply_filter` and `apply_filter_all_threads`
return success for the reproduced all-allow program, even though the caller's
requested filter was not installed. Programs with 4,097 and 65,536
instructions fail at the kernel as expected; the wrap to one is the dangerous
case.

Chio's current compiler path rejects generated filters at the kernel maximum
before installation, so this review did not demonstrate a Chio policy escape.
The unsafe conversion remains inside the selected confinement dependency and
cannot be certified unchanged.

## Selected repair

The main, fuzz and generated Docker workspaces select
`third_party/seccompiler-chio`. The production diff replaces the truncating
cast with a checked conversion before `PR_SET_NO_NEW_PRIVS`. An unrepresentable
length returns the existing `BackendError::FilterTooLarge` error and makes no
process-state change. No version, dependency edge, filter compiler or syscall
sequence changes for representable programs.

New tests cover both installation APIs with the original 65,537-instruction
input. They require the exact error length and prove `PR_GET_SECCOMP` remains
zero. The original reproduction, source inventory and validation output are
retained under `output/process-security-20260915/`.

On Linux x86_64, all 32 unit and integration tests and 5 documentation tests
pass on the final immutable fork source. Strict Clippy passes for all features
and targets with warnings denied. The only additional source adjustment is a
documentation-list indentation required by the current Clippy version; it has
no runtime effect. Terminal logs are retained in
`selected-seccompiler-validation/`.

## Review boundary

The crate compiles policies into classic BPF and installs them through
`prctl(PR_SET_NO_NEW_PRIVS)` and `seccomp(SECCOMP_SET_MODE_FILTER)`. Its unsafe
code passes live slices and C-layout structures to the kernel; the kernel
copies the program during the call. Rule construction bounds syscall argument
indices and generated program length. Architecture validation is explicit for
x86_64, aarch64 and riscv64. JSON parsing is feature gated and resolves syscall
names through fixed architecture tables.

The repair prevents semantic substitution at the raw installation boundary.
It does not prove a specific application policy is sufficient, and it does not
replace Linux cage qualification on the final frozen candidate.
