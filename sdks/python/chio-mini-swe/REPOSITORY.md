# Run against a repository

`chio-mini-swe-repository` imports a selected local Git commit, serves the
`execute` tool, persists completed workspace changes and exports a Git patch.
Use it as the execution server in the [native coding operator](OPERATOR.md).
The source checkout is read during import. Dirty and untracked files stay in
that checkout; commands operate on the imported snapshot.

The service requires a non-root Linux operator, `/usr/bin/git`, and a local
Docker engine at `/var/run/docker.sock` with cgroup v2, built-in seccomp and
memory, swap, CPU and PID controls. The qualified profile uses rootful Docker
without user remapping. Docker and the installed service are trusted operator
components. The coding worker receives the Chio tool route.

## Prepare images and a workspace

Provide two immutable local image IDs:

- The execution image contains Bash, GNU `timeout`, Git and the project's
  runtime and dependencies. Commands have no network access, so prepare
  dependencies in the image before starting a task.
- The helper image contains `/bin/sleep` and GNU `/bin/tar`. It imports and
  snapshots the workspace, outside the command container's process namespace.

Both images must support UID/GID 65534 and declare no extra writable volumes.
The [qualification image builder](../../../examples/mini-swe-recovery/build_repository_image.py)
adds Git to the pinned Python base from a worker image record:

```sh
python examples/mini-swe-recovery/build_repository_image.py \
  --worker-image-file /private/worker-image.json \
  --output /private/repository-images.json
```

The resulting `execution_image` is the command image ID; `image` remains the
native coding worker image ID. Resolve the record's `base` to a local ID with
`docker image inspect --format '{{.Id}}' <base>` for the helper. The builder
records the Dockerfile digest, Git version and resulting image ID. Package
repositories may change between builds; execution is pinned to the built ID.

```sh
chio-mini-swe-repository init \
  --repository /code/project \
  --revision <commit-or-ref> \
  --image sha256:<execution-image-id> \
  --helper-image sha256:<helper-image-id> \
  --timeout-seconds 60 \
  --state /tmp/project-repository
```

Initialization resolves the selected commit, applies Git archive export
attributes and creates a private workspace. Submodules are rejected. Include
their needed contents in the committed source tree or execution image first.
Files, executable bits, binary contents and contained relative symlinks are
supported. Paths that escape the workspace, cyclic symlinks, special files and
oversized archives are rejected.

Git object reads use fresh configuration, so source filters, archive commands,
replacement refs and promisor remotes cannot execute or substitute another tree
during import. The installed Git binary and local object storage remain trusted.

For a task in a large repository, repeat `--source-path` to import only the
committed files and directories it needs. Paths stay relative to the repository
root inside `/workspace`:

```sh
chio-mini-swe-repository init \
  --repository /code/arc --revision <commit-or-ref> \
  --source-path sdks/python/chio-process \
  --image sha256:<execution-image-id> --helper-image sha256:<helper-image-id> \
  --state /tmp/process-sdk-task
```

Selection accepts 1 to 64 literal, canonical relative paths, with at most
16 KiB of encoded path data. Globs and Git pathspec magic are not expanded.
Every path must exist in the selected commit; duplicates, overlapping roots
and `.git` paths are refused. Unselected files and submodules are not imported
or charged against workspace size; selected submodules are still rejected.
Git export attributes continue to apply. Omitting `--source-path` imports the
full exportable tree and preserves the existing behavior.

The selected paths are bound into the signed tool manifest's configuration
digest and every completed command receipt. Before publishing a new revision,
the service rejects files or directories outside those roots, except their
parent directories and the sandbox's private Git metadata. A violation stops
the workspace, cleans owned containers and retains the prior committed
revision. This is a snapshot publication boundary; commands can still use the
container's temporary directory. Run package commands inside the selected
directory and place temporary build outputs in `/tmp`.
Retained snapshots are checked against the same scope before any container
receives them; a mismatch stops before dispatch and leaves the command journal
unchanged.

Scoped workspaces use configuration `chio.repository.workspace.v3` and the
same shared snapshot storage as v2. Older packages reject v3. A recipient must
pass the same independently selected `--source-path` values to `verify-export`;
the verifier never takes its expected scope from the received bundle. The
exported patch retains repository-relative paths and can be reviewed against
the original source commit.

The sandbox starts with a new local Git history over the imported files. Its
initial commit differs from the source commit recorded in the workspace
metadata. No source repository credentials, remotes, hooks, configuration or
history are copied. Git metadata created inside the sandbox persists between
commands, so `git status`, `git diff` and local commits work when the execution
image contains Git.

## Connect the service to the native host

Use this installed command in the execution server's signed launch policy and
native host configuration:

```json
["/private/coding-venv/bin/chio-mini-swe-repository", "serve", "--state", "/tmp/project-repository"]
```

Set `request_timeout_seconds` on this server in the native host configuration
to the repository command deadline plus 120 seconds. For the 60-second command
deadline above, use `"request_timeout_seconds": 180`. This reserves time for
workspace setup, snapshot validation, cleanup and the tool response. The host
accepts 1 to 3600 seconds and otherwise defaults to 60 seconds, which is too
short for this repository profile. Changing this setting requires provisioning
a new host configuration before starting the task.

Initialization and discovery keep separate 10-second host deadlines. Run
explicit repository recovery before starting the host when pending resources
need cleanup. An external host timeout can terminate the service before it
finishes cleanup; inspect both retained states and recover before continuing.

The tool is named `execute`. Its manifest binds the workspace identity, source
commit and configuration digest, including the selected images and deadline.
Provision that exact manifest and command through the existing native launch
policy flow. Changing configuration requires deliberate reprovisioning and a
new coding task. The service does not issue capabilities or create a policy.

Point the coding operator profile at this server and tool, set the environment
directory to `/workspace`, and run its `prepare` and `run` commands. The service
serializes access to a workspace. Separate tasks should use separate workspaces.
Set the agent's `wall_time_limit_seconds` and native worker attempt
`timeout_seconds` high enough for the selected host request budget and the rest
of the task. The worker's socket client uses the agent wall-clock limit instead
of a separate fixed 60-second timeout. Direct `ProcessClient` users must also
set their client timeout above the host request budget.

## Persistence and limits

Each command gets a new container and a bounded temporary workspace volume.
The previous committed snapshot seeds that volume. After the command exits,
the service removes its entire container, including background processes. A
separate helper then reads the workspace. The service validates the archive,
persists it, removes the helper and volume, and commits the new revision before
returning the tool result.

| Resource | Bound |
| --- | --- |
| Workspace volume | 64 MiB, including sandbox Git data |
| Each container | 512 MiB memory, no extra swap, one CPU, 64 PIDs |
| Each container's temporary directory | 16 MiB |
| Raw command output | 512 KiB combined stdout and stderr |
| Encoded tool response | 1 MiB including duplicated JSON content, escaping and request ID |
| Individual file | 16 MiB |
| Snapshot | 8,192 entries, 64 MiB file content, 80 MiB archive |
| Retained snapshot storage | 256 MiB accounted storage, with space reserved before dispatch |
| Commands per workspace | 128 |
| Command deadline | 1 to 300 seconds, selected at initialization |
| Total successful operation | Command deadline plus 90 seconds for setup, snapshot and cleanup |

New workspaces store immutable archive segments and a small index per snapshot.
Unchanged file bodies, including sandbox Git objects, are shared across revisions.
Reads verify each segment and reconstruct the exact original archive bytes and
SHA-256 identity. Receipt bindings and exported archive formats stay the same.
Every segment is durable before its index is published, and the journal advances
only after the candidate snapshot is durable and container cleanup succeeds.

The 256 MiB limit charges each object and index at least 4 KiB to bound small-file
growth. It is an accounting limit, not an operating-system filesystem quota.
Before dispatch, the service reserves an 80 MiB archive plus worst-case segment
and index overhead. Large changes or many files can still exhaust this bound.
All historical snapshots and orphan objects from failed writes remain retained
and charged; there is no automatic pruning. A refusal before dispatch leaves
the command journal unchanged. A write failure after execution stops the workspace
and retains the previous committed revision.

The private configuration identifies this storage layout as
`chio.repository.workspace.v2`. The current package continues to read and write
existing v1 workspaces using their original full archives; it does not migrate
them. Older packages reject v2 workspaces. Existing v1 configuration stays
unchanged; package updates still require the usual installation and launch-policy
identity checks.

Containers use read-only root filesystems, no network, no capabilities and
no-new-privileges. They receive the temporary volume, without host source
directories, a Docker socket, worker credentials or provider credentials.
Commands may return a nonzero exit code, such as failing tests, and still have a
known completed result. Timeout, output overflow, invalid snapshots and failed
cleanup stop the workspace without promoting a partial revision.
The serialized response is checked before promotion; escaping can make the
effective output limit smaller than the raw byte limit.

Container creation intents and exact identities are durable before execution.
Recovery verifies the original Docker engine, names, labels and recorded IDs
before removing resources. Ownership mismatches leave the state unresolved.

```sh
chio-mini-swe-repository status --state /tmp/project-repository
chio-mini-swe-repository recover --state /tmp/project-repository
```

Starting `serve` also recovers pending resources before accepting calls. An
interrupted command remains stopped after cleanup. It is not automatically
redispatched. The last completed snapshot remains available for inspection;
partial in-container changes are discarded during recovery. A completed service
transition can still precede an unknown native-host outcome if the host dies
before recording the reply. Consult both host and repository status.

The running service enforces its deadline and also uses an in-container timeout.
Control subprocesses share the total operation budget. Failure cleanup gets
separate bounded Docker calls; an unavailable engine can still require explicit
recovery after the host times out. Deadline checks before commit prevent an
expired operation from promoting its candidate snapshot.
The latter is not an independent security watchdog. After abrupt service death,
restart or explicit recovery is required to establish cleanup. Snapshots persist
on the operator filesystem, independently of temporary containers and volumes.
They contain source code, outputs and sandbox Git history; keep that state private.

## Export and verify changes

Stop the native run before exporting. A plain export produces the last completed
workspace and marks whether execution was interrupted:

```sh
chio-mini-swe-repository export --state /tmp/project-repository --out /tmp/project-export
```

The new private directory contains `baseline.tar`, `workspace.tar`,
`changes.patch`, `commands.json`, `configuration.json` and `manifest.json`. Container-controlled Git
metadata is removed before host-side patch generation. The patch includes
tracked modifications, deletions and new files visible to Git; ignored new
build artifacts remain in the workspace archive. Export does not apply the
patch to the source checkout.

To bind the exported changes to Chio evidence, first obtain the native coding
result and original receipts with `chio-mini-swe result`, then run:

```sh
chio-mini-swe-repository verify \
  --state /tmp/project-repository \
  --chio /private/bin/chio \
  --receipts /tmp/coding-result/receipts.ndjson \
  --kernel-key /tmp/coding-result/kernel.pub \
  --server-id sandbox \
  --out /tmp/project-verified
```

Use the kernel key pinned during task preparation. This command independently
verifies every supplied receipt with Chio, matches each execution command and
its complete output hash, and checks the ordered snapshot transitions against
retained archives. The output adds the original receipts, public key and
`receipt-binding.json`. The configuration and content digests in successful tool
results are covered by the signed output hash.

Verification refuses missing, duplicate, unrelated, incomplete or mismatched
execution evidence. If an output guard redacted the service's result, the raw
retained result cannot reproduce that signed output hash; binding verification
refuses it. Plain export remains available for inspection. Receipt binding
establishes what the configured service reported and what artifacts were
retained. It does not establish that a patch solves the task or that tests are
complete. Review the patch and validate it before applying or publishing it.
Receipt input is bounded to 64 MiB and 1,024 records, matching the native
verifier's aggregate byte bound.

## Verify a received patch bundle

A reviewer can verify a received export using their own repository clone,
the full source commit they expect, and a kernel public key obtained from the
operator through a trusted channel:

```sh
chio-mini-swe-repository verify-export \
  --bundle /downloads/project-verified \
  --repository /code/project \
  --revision <full-40-or-64-character-source-commit> \
  --chio /private/bin/chio \
  --kernel-key /private/trusted-operator-kernel.pub \
  --server-id sandbox
```

The supplied key and execution server identify the operator evidence the
reviewer trusts. Do not choose that key solely because it arrived inside the
bundle. The command verifies the original signatures afresh, checks the exact
command/output bindings and configuration, and compares the baseline archive
against the selected Git commit. It then authenticates the final workspace
contents and reconstructs the Git patch. It outputs a JSON review report with
the verified source, server, key, workspace identity and content digests.

Verification needs the installed package, native Chio verifier and `/usr/bin/git`.
It works without Docker, a provider credential, the producer's private journal
or intermediate snapshots. The source checkout stays unchanged, including
dirty and untracked files. Only private temporary directories are written;
bundle files are captured with bounded regular-file reads, and archive paths
are validated before materializing them for patch reconstruction.

The report authenticates the intermediate snapshot hash chain. Intermediate
archive bytes are absent from the bundle, so they cannot be rechecked here.
Ignored new files can remain in the authenticated workspace archive without
appearing in the Git patch. Patch reconstruction requires byte-identical Git
diff output; a Git version that produces a different representation is refused.
No repository code, hooks, filters, tests or model instructions are executed.
This command verifies evidence and changes, not whether the change solves the task.

Older exports lacking `configuration.json` must be exported again using the
current package. Existing private workspace state is compatible. Plain exports
without original receipts and `receipt-binding.json` cannot pass this review.
