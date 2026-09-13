# SensorGroundedAdmission.lean: build log

This file records the build environment and the exact commands used to
check `SensorGroundedAdmission.lean`. The Lean source lives beside this
note.

The module is paper-local. It is not imported by the substrate's root
module `Chio.lean`, not built by the substrate's `lake build`, not
listed in `formal/proof-manifest.toml`, and not in
`formal/theorem-inventory.json`. It is checked by hand against the
substrate's Lean root, which is where the modules its imports name
(`Chio.Treaty.PredicateLang` and `Chio.Treaty.Intersection`) are built.

## Environment

```
Lake version 5.0.0-src+7e01a1b (Lean version 4.28.0)
```

Lake binary at `~/.elan/bin/lake`, managed by elan. The release is the
one pinned by `formal/lean4/Chio/lean-toolchain`.

## Verification procedure

One command, run from the substrate's Lean root, with no copy into the
root's source tree and no edit to its root module:

```bash
cd formal/lean4/Chio
lake env lean ../../../docs/papers/sensor-grounded-admission/lean/SensorGroundedAdmission.lean
```

The command exits 0 and prints nothing: no errors, no warnings, no
`sorry`, no project-local `axiom`. Running it requires the root's own
`lake build` to have produced the oleans the imports resolve against.

The same check runs inside `supplementary/lean-source.tar.gz`, which
packages a byte-identical copy of this module alongside the three
substrate Treaty modules that form its import closure; see
`supplementary/README.md`.

## Axiom audit

Appending these four lines to a scratch copy of the module and running
the command above on the copy reports:

```
#print axioms Chio.Treaty.SensorAttestation.admission_predicate_separates_healthy_and_degraded_witnesses
#print axioms Chio.Treaty.SensorAttestation.partition_contingency_mode_iff_degraded_subset
#print axioms Chio.Treaty.SensorAttestation.healthy_attestation_required_for_destructive_admission
#print axioms Chio.Treaty.SensorAttestation.degraded_sensor_admission_requires_re_admission_witness
```

```
'Chio.Treaty.SensorAttestation.admission_predicate_separates_healthy_and_degraded_witnesses' depends on axioms: [propext,
 Classical.choice,
 Quot.sound]
'Chio.Treaty.SensorAttestation.partition_contingency_mode_iff_degraded_subset' depends on axioms: [propext]
'Chio.Treaty.SensorAttestation.healthy_attestation_required_for_destructive_admission' depends on axioms: [propext]
'Chio.Treaty.SensorAttestation.degraded_sensor_admission_requires_re_admission_witness' depends on axioms: [propext,
 Quot.sound]
```

No `sorry` axiom appears. `propext`, `Classical.choice` and `Quot.sound`
are Lean's standard kernel axioms, the same ones that underwrite the
rest of the Chio Lean project.

## Effect on the substrate

None. The check reads the root's build products and writes nothing into
`formal/lean4/Chio`; the substrate's git state is untouched by a
verification run. The module of record stays at
`docs/papers/sensor-grounded-admission/lean/SensorGroundedAdmission.lean`.
