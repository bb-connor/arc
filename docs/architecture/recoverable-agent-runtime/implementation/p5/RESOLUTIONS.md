# P5 final review resolutions

The immutable [fresh reviewer report](FRESH-REVIEW.md) identified two Important
findings on the original 74-input binding. The primary executor addressed both
in one test-first fix pass. This record distinguishes that fresh review from
primary review of the final changes. Full current-source local acceptance is
still running; the verification record controls completion.

## P1: parent cancellation ordering

The actual native Linux regression reached the cancelled parent before native
admission and delivered incorrectly. The fix rechecks parent activity after the
before-admission cutpoint and after commit, immediately before sink delivery.
The process broker performs its final running-state read under the same journal
mutex as cancellation. Cancellation completed before that read withholds bytes;
a later cancellation cannot retract an already authorized crossing. No native
transaction or journal lock spans arbitrary sink I/O.

The corrected regression passed all three orderings: before admission, after
commit, and before delivery. Independent SQL checks retain zero/one admissions
and zero/two evidence consumption; the sink remains empty and a previously
prepared replay handle refuses. A new read from the cancelled child correctly
refuses and is not weakened to facilitate replay.

Evidence: `evidence/diagnostics/native-20261004/p1-red-complete-fixture.log`
and `p1-green-final.log`. Earlier fixture failures are retained separately.

## P2: ordinary lineage depth

The original 32-entry scan rejected an ordinary tree that the process runtime
allows to depth 64. The regression reproduced the unavailable context. The
resolver now scans the existing 65-entry ordinary capacity and applies the
32-entry confinement bound only after detecting a confinement boundary.

The regression passes through actual native admission, preserving the original
root lineage and epoch with one endpoint call and one tree call charge. All 17
owning process tests pass. Evidence: `ordinary-depth-red.log`,
`ordinary-depth-green.log` and `ordinary-depth-suite.log` in the diagnostic directory.

## Real Linux acceptance corrections

- The selected cage compiler always supplies exactly `LANG=C`, `LC_ALL=C`,
  `TZ=UTC`. The binding spec permits proven host-fixed templates. A real Linux
  RED rejected the valid compiled profile; exact three-value validation now
  accepts it while every added or mutated environment value refuses. The paired
  case proves parent environment canaries never reach the child and a custom
  allowed environment refuses before boundary reservation.
- Positive fixtures now publish from an actually imported restricted native
  parent. Adoption intentionally retains unknown influence. A separate real
  Linux correct-projection test proves unknown provenance still withholds return
  admission. No production provenance check changed.
- The strict preparation fixture expects the two new public base digest fields
  and independently compares their pre-stdio values. All original private path
  and secret exclusions remain. The initial 26/27 result is retained; the final
  campaign passes all 72 inventory tests, 27 required runtime probes and 10 real
  helper mutants.
- The isolated guest Git snapshot needed local Git LFS filters. Both unchanged
  Swift archive hashes independently matched the host. The initial failed
  source-binding check remains retained. Temporary diagnostic source was
  restored byte-for-byte and compilation refreshed before final qualification.

The final native Linux campaign passes all ten required cases with eleven
measured static PIE images on binding
`562a3c3556f31e5afedbd7c7a426e542cc5e8cd51c28a7a43d8e9704ba4e9bc4`.
No provider/model context, non-Boolean return, nested launch, recipient effect
exactly-once, covert channel, hosted CI or production deployment is qualified.
