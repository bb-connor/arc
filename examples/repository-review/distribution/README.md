# Run an adaptive Chio review without a checkout

This kit contains the native Chio host, the repository review application,
four Chio Python SDK wheels, and the application's locked third-party wheels.
It reviews committed Git changes and creates reviewer processes at runtime.
The default mode produces a deterministic inventory. It does not call a model,
execute repository code or establish semantic correctness.

Use Linux on the architecture and Python major/minor version recorded in
`manifest.json`. Python needs `venv` and `pip`; Git must be installed. Rust,
Node, uv, a Chio checkout and a package registry are not needed to run the kit.
The native executable and compiled wheels also require a compatible Linux
userspace. This is a development preview for the producing platform.

## Review an existing repository

Extract the archive into a directory you control. From that directory:

```bash
python3 -I review.py prepare \
  --repo /path/to/repository --base HEAD~1 --head HEAD \
  --state /tmp/my-chio-review
python3 -I review.py run --state /tmp/my-chio-review
```

Use a new state directory with an existing parent. The native host rejects
group- or world-writable ancestors unless they are sticky, as `/tmp` is.
Preparation installs the bundled wheels offline into a private environment,
checks their versions and import locations, captures the Git snapshot, and
initializes the process host. It never overwrites an existing state directory.
If preparation fails, retain its private logs and use a new directory.

The run prints the paths to `run/report.md` and `run/evidence.json`. The
coordinator selects up to eight reviewers by default. Use `--max-reviews`,
`--max-parallel`, `--max-rounds` and `--max-calls` during preparation to set
the application's bounds. A whole review can finish with one worker slot:
the coordinator checkpoints its join and releases the slot while children run.

The supplied receipt verifier can check the exported original receipts:

```bash
bin/chio receipt verify --input /tmp/my-chio-review/run/receipts.ndjson \
  --trusted-kernel-pubkey /tmp/my-chio-review/run/kernel.pub
bin/chio process status --state /tmp/my-chio-review/run/host
```

The public key is pinned during trusted initialization. Establish its trust
independently before accepting an evidence package from somebody else.
Signatures and signed invocation parameters do not prove model correctness,
arbitrary tool output, log completeness or complete causal provenance.

## Resume and configure a model

Repeat the same `run` command. Completed workers stay completed. Pending
graphs retain their original tool identities, and the native runner owns
bounded retries, direct worker termination and child scheduling. Keep both
the full private state directory and the kit at their original locations.
Capabilities expire one hour after preparation; this profile cannot renew them.

Before resuming, the launcher checks the bundled files and the files and
versions of prepared dependencies. SDK drift is rejected before importing
the changed SDK. The application separately checks its source, native binary,
snapshot, authority configuration and executable plan. These checks detect
accidental drift. They do not sandbox same-user code or attest installed
bytecode, provider packages, environment variables or the supplied binary's
build provenance. Trust the kit's supplier separately.

For model planning, prepare with `--model-factory your_package:create`.
Install your trusted factory and provider integration into
`/tmp/my-chio-review/venv` before running. Additional packages are allowed;
they must preserve the versions and files of the prepared runtime. The factory
accepts `coordinator` or `reviewer` and returns a configured LangChain chat
model. Use private environment variables for credentials. `PYTHON*` import
overrides are removed, so install the factory as a package rather than relying
on `PYTHONPATH`. Added provider code is not included in the kit's dependency
pins. Model API calls and token costs are outside Chio tool admission.

See `application/ADAPTIVE.md` for assignment validation, tool scopes, snapshot
limits, attempt ceilings, guarded mailbox handoffs and unknown spawn outcomes.
Qualification uses a scripted factory. Live model quality and independent
application adoption remain unverified.

## Qualify an extracted kit

```bash
python3 -I qualify.py --kit "$PWD"
```

Qualification prepares a real Git fixture using an installed environment,
checks external SDK imports and offline installation, runs and repeats a
two-child review, terminates the launcher after known spawn results, and
recovers the original submissions. It also rejects changes to application
and installed SDK files before importing the modified SDK.
It then runs the full adaptive recovery suite through the installed packages:
runtime decomposition, one-slot joins, worker and host death, original receipt
replay, invalid plans, model round limits, authority denials and corrupted
evidence. Success exports nonsecret evidence under `evidence/`. Failure retains
the private diagnostic directory and returns a nonzero status. Use a fresh kit
for another qualification run; existing evidence is not overwritten.

## Build from source

From a Chio checkout, with uv available and the native CLI already built:

```bash
python3 scripts/package-repository-review.py --chio target/debug/chio \
  --output /tmp/chio-review-kit
python3 -I /tmp/chio-review-kit/qualify.py --kit /tmp/chio-review-kit
tar -C /tmp/chio-review-kit -czf /tmp/chio-review-kit.tar.gz .
```

Building downloads wheels selected by the application's checked-in `uv.lock`
and builds local SDK wheels. Installing the resulting kit uses only local
artifacts with required hashes and no dependency resolution. The kit manifest
records file hashes, selected package versions and whether the source checkout
was dirty. It does not establish how the supplied native executable was built.
This command creates no release tag and publishes no registry package.
