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

- `lean-source.tar.gz` Lean 4 project that checks the four
  sensor-grounded theorems. It carries `lean-toolchain` (pinning
  `leanprover/lean4:v4.28.0`, the substrate's current release),
  `lakefile.lean` with no external dependency, `lake-manifest.json`,
  a `Chio.lean` root module, the three substrate Treaty modules that
  form the sensor module's import closure
  (`PredicateLang`, `IntersectionSyntactic`, `Intersection`), the
  sensor module itself at `Chio/Treaty/SensorGroundedAdmission.lean`,
  and a build README. The packaged sensor module is byte-identical to
  `../lean/SensorGroundedAdmission.lean`
  (SHA-256 `356b2420543b73e9a4e7b9022f54b18bf739df569123eef85934dcd260c5a3bc`).
- `proof-manifest.toml` Snapshot of the four theorems, their Lean
  modules and fully qualified declarations, the paper section in which
  each is stated, and the axiom set reported by `#print axioms`.
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

With `elan` installed, the tarball checks with:

```
tar xzf lean-source.tar.gz
cd chio-lean
lake build
lake env lean Chio/Treaty/SensorGroundedAdmission.lean
```

`lake build` builds the three substrate Treaty modules, printing the
`#eval` information lines those modules carry and reporting no warnings
or errors. `lake env lean` then elaborates the paper-local module
against them and exits 0 with no output. The package keeps the two
steps separate so the module is checked exactly as it is in the
repository: from outside the root module, never registered in it. A
cold toolchain install dominates the wall time; the build itself takes
a few seconds. The sources contain no `sorry` and no project-local
`axiom`.

The same check runs against the substrate's own Lean root, without the
tarball, as `cd formal/lean4/Chio && lake env lean ../../../docs/papers/sensor-grounded-admission/lean/SensorGroundedAdmission.lean`.
`../lean/build-log.md` records that run.

## Verifying the axioms

The axiom set reported by Lean's `#print axioms` for each theorem is
recorded in `proof-manifest.toml` (and `theorem-inventory.json`). To
reproduce, append the four `#print axioms <name>` lines listed in
`../lean/build-log.md` to a scratch copy of
`Chio/Treaty/SensorGroundedAdmission.lean` and run `lake env lean` on
the copy.

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

## Regenerating the package

The tarball is a derived artifact. Rebuild it from the repository
whenever the paper-local module or the substrate's Treaty modules
change, so that the packaged copy never drifts from the module of
record:

```
mkdir -p chio-lean/Chio/Treaty
cp formal/lean4/Chio/Chio/Treaty/{PredicateLang,IntersectionSyntactic,Intersection}.lean \
   chio-lean/Chio/Treaty/
cp docs/papers/sensor-grounded-admission/lean/SensorGroundedAdmission.lean \
   chio-lean/Chio/Treaty/
cp formal/lean4/Chio/lean-toolchain chio-lean/lean-toolchain
# chio-lean/lakefile.lean: the substrate lakefile with the `require` line
# and the non-Chio libraries dropped.
# chio-lean/Chio.lean: imports of the three Treaty modules above.
# chio-lean/README.md: build and axiom instructions for reviewers.
tar --sort=name --mtime='<date>' --owner=0 --group=0 --numeric-owner \
    -czf docs/papers/sensor-grounded-admission/supplementary/lean-source.tar.gz \
    chio-lean
```

Then re-run the verification commands above on a fresh extract,
and refresh the SHA-256 recorded under Files.
