# Supplementary Materials

Paper: "Sensor-Grounded Admission: Polity Receipts with Attested
Substrate State"
Venue: USENIX Security 2027 (Cycle 1)

This package makes the Lean 4 mechanization behind the paper's formal
claims auditable by artifact reviewers. It contains a self-contained
tarball of the Lean sources, a TOML manifest and JSON inventory that
name each theorem and its axiom dependencies, and these instructions.

The mechanization is paper-local. Its canonical source is
`../lean/SensorGroundedAdmission.lean`, kept beside the paper; it is not
imported by the substrate's root module, not built by the substrate's
`lake build`, and not listed in the substrate's
`formal/theorem-inventory.json`. It is checked by hand against the
substrate's Lean root as described in `../lean/build-log.md`.

## Files

- `lean-source.tar.gz` Lean 4 project that compiles the four
  sensor-grounded theorems. Includes `lean-toolchain` (pinning
  `leanprover/lean4:v4.28.0-rc1`), `lakefile.lean`, `lake-manifest.json`,
  a `Chio.lean` root module, a snapshot of the substrate's `Chio/` subtree
  (Core, Capability, Proofs, Spec, Treaty) taken when the package was
  assembled in May 2026, and a build README. The snapshot predates the
  substrate's current Treaty modules, and the tarball's README names the
  fourth theorem by an older name; the tarball's copy of the
  sensor-grounded module is byte-identical to `../lean/SensorGroundedAdmission.lean`.
- `proof-manifest.toml` Submission-time snapshot of the four theorems,
  their Lean modules and fully qualified declarations, the paper
  section in which each is stated, and the axiom set reported by
  `#print axioms`.
- `theorem-inventory.json` Same content, JSON-shaped for tool
  consumption.

## Sensor-grounded theorems

All four are proved in the paper-local module
`lean/SensorGroundedAdmission.lean` beside the paper (tarball path
`Chio/Treaty/SensorGroundedAdmission.lean`), under the
`Chio.Treaty.SensorAttestation` namespace:

1. `admission_predicate_separates_healthy_and_degraded_witnesses`
   (Section 4, headline existence theorem)
2. `partition_contingency_mode_iff_degraded_subset` (Section 4,
   partition-contingency biconditional)
3. `healthy_attestation_required_for_destructive_admission`
   (Section 4, destructive-admission projection)
4. `degraded_sensor_admission_requires_re_admission_witness` (Section 4,
   amendment re-admission)

## Verifying the build

With `elan` installed, the tarball builds with two commands:

```
tar xzf lean-source.tar.gz
cd chio-lean && lake build
```

A cold cache takes roughly 3-5 minutes. The build succeeds without
warnings, without `sorry`, and without any project-local `axiom`. To
check the paper-local source against the substrate's current Lean root
instead of the snapshot, run `lake env lean` on it from
`formal/lean4/Chio` as described in `../lean/build-log.md`.

## Verifying the axioms

The axiom set reported by Lean's `#print axioms` for each theorem is
recorded in `proof-manifest.toml` (and `theorem-inventory.json`). To
reproduce, append the four `#print axioms <name>` lines listed in
`../lean/build-log.md` to `Chio/Treaty/SensorGroundedAdmission.lean` and
run `lake env lean Chio/Treaty/SensorGroundedAdmission.lean` (the
tarball's own README lists the fourth theorem under an older name).

Only standard Lean kernel axioms appear:
- `admission_predicate_separates_healthy_and_degraded_witnesses`
  depends on `propext`, `Classical.choice`, `Quot.sound`.
- `partition_contingency_mode_iff_degraded_subset` depends on
  `propext`.
- `healthy_attestation_required_for_destructive_admission` depends
  on `propext`.
- `degraded_sensor_admission_requires_re_admission_witness` depends on
  `propext`, `Quot.sound`.

No project-specific axioms are introduced.
