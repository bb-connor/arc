# Six-pair integration intake

The six independent exercises remain unperformed because no outside operators
are available. This package makes their evidence mechanically reviewable. It
extends the [existing preregistration](../kernel-work/results/comparison-preregistration.md)
and [original trial](../../papers/verifiable-work/trial/README.md), preserving
Q1-Q10, H1-H5, C0-C3, the pilot and held-out power design. It does not replace
those requirements or contact participants.

## Operator workflow

1. Copy `operator-template/` to a new evidence directory. Preserve its 12 rows
   and counterbalanced order. Register real operator IDs in `manifest.json`.
   Freeze `scheduled_incidents` before execution: its keys are `I1/Chio`,
   `I1/B1`, through `I6/B1`, and each value lists that arm's globally unique
   scheduled incident IDs. The independently attested manifest revision must
   predate work. Each pair uses the same implementer, task corpus, model pin, trust profile
   and budget profile. Retain full source, configuration, prompt and hardware
   pins in the committed source/attestation artifacts. Pin equivalent provider
   semantics even where independently written adapters have different source.
2. Preserve every attempted or abandoned run. An event log is JSONL with one
   object per attempt: `attempt_id`, `status` (`succeeded`, `failed`, `cancelled`),
   decimal-string `hands_on_hours`, `incident_id` (null for unrelated work),
   boolean `recoverable_incident` and
   `recovered_without_repair`, integer `database_edits` and `bespoke_repairs`.
   Attempt IDs are unique across the package. All attempts and repairs belonging
   to one incident retain its scheduled incident ID, in chronological order.
   `recoverable_incident` must equal whether that ID is present. Log failed
   effort too. Split interrupted attempts into distinct entries; never replace
   a failure with its later retry. Record an unavailable scheduled incident as
   an unsuccessful attempt; never remove it from the denominator. A completed
   incident cannot be reopened under the same ID.
3. Enter all preregistered costs and counts. Repeated hands-on time includes all
   active effort during the repeated exercise, including failed work, debugging
   and assistance. Record training, assistance and debugging hours separately
   as annotations, not amounts to subtract. Initial platform effort stays
   separate. These totals require operator review; the tool cannot observe
   omitted work or establish whether self-reported time is authentic.
4. Retain source bundles/manifests, adapter diff, raw event logs and operator
   attestations as files. For each artifact put its SHA-256 and relative path
   into `artifacts`. The CSV's artifact fields contain those hashes. Source
   bundles can include Git commit IDs; the CSV hash commits the retained bundle.
   Paths may not escape the evidence root, including through symlinks.
5. Obtain a matched safety/progress/quality judgment with its supporting traces.
   The committed JSON has an `exercises` object with I1-I6 entries, each carrying
   boolean `safety_matched`, `progress_matched`, `quality_matched`. Each manifest
   adjudication repeats those values and names `artifact_sha`; the CSV's
   `quality_adjudication` hashes must agree. Both true and false judgments are
   retained. The validator checks consistency, not the adjudicator's competence.
6. Run:

       python3 -B docs/research/kernel-continuation/trial_intake.py /path/to/evidence/manifest.json

Exit 0 means the supplied records are mechanically complete. Exit 2 means an
unresolved record error. The result reports all six paired time ratios, their
median, pooled recovery fractions for both arms and the numerical primary
threshold. It never returns empirical acceptance: independently operated
infrastructure, authentic effort, adjudication, task quality and completeness
of supplied logs still require an independent audit. Mode `independent` records
the intended study mode and does not certify those facts.

Incidents are counted once, across all attempts. A successful final retry can
count as unassisted recovery only if no attempt in that incident used database
edits or bespoke repairs. An earlier repair cannot be hidden by a clean final
attempt. Repairs require an incident ID. The collector requires complete coverage
of the supplied schedule; the independent auditor must check that the schedule
was fixed beforehand and matches the preregistered fault workload.

The primary numerical threshold is the preregistered median Chio/B1 ratio <=
0.50, matched safety/progress/quality and Chio recovery without database edits or
bespoke repair >= 0.95. All failed attempts remain in effort and repair counts.
Zero B1 denominators and missing incidents are unresolved. Report the six pairs
as exploratory; this is not a population confidence claim or a ratio of summed
effort. Exact rational arithmetic decides the threshold and reconciles logged
effort. Displayed decimals are rounded; exact ratio numerators/denominators and
recovery counts accompany them. The numeric transport accepts nonnegative values
up to 1e18, at most 18 significant digits and resolution no finer than 1e-24,
with integral counts. Unsupported precision returns a structured record error.

## Dry run

`synthetic-demo/` contains fabricated inputs clearly marked SYNTHETIC, including
failed attempts. It exercises the collector and produces a deliberately chosen
0.5 median. No person, real task or provider was measured. The result keeps
`empirical_acceptance: false` even though its numerical threshold is met.

    python3 -B docs/research/kernel-continuation/trial_intake.py docs/research/kernel-continuation/synthetic-demo/manifest.json

The empty operator template intentionally exits 2. Do not fill it with guessed
measurements, local build times or these synthetic values. Additional fixtures
can be generated in a new disposable directory with `trial_fixture.py`.
