# chio-runtime-harness Architecture

`chio-runtime-harness` drives live runtime loopback scenarios through admission, kernel execution, treaty context construction, proof assembly, and evidence output. It is a test and tooling crate, but it still owns security-sensitive evidence shape because its artifacts are consumed as regenerated proof material.

Scenario normalization accepts exactly one input shape: either the legacy top-level single-step fields or the explicit `steps` list. The harness rejects ambiguous mixed scenarios so a fixture cannot carry ignored top-level admission data while executing a different step list.

Evidence output is written through the local JSON helpers. Those helpers canonicalize hashes where needed, record manifest entries, and reject unsafe relative paths before writing artifacts below the output directory.
