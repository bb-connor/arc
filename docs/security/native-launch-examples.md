# Enforced native launches in examples

Native MCP tools require an Enforced signed reference-runtime policy. Disabled
and Shadow stages can prepare offline artifacts but cannot launch processes.
The shared shell helper, Python process SDK helper, Docker entrypoint and native
conformance runner all use the same explicit operator configuration:

| Variable | Required value |
| --- | --- |
| `CHIO_CAGE_INIT` | Absolute path to the reviewed static `chio-cage-init` executable for this host. |
| `CHIO_RECEIPT_ANCHOR_ROOT` | Absolute path to the independently provisioned receipt rollback anchor directory. |
| `CHIO_CAGE_READ_PATHS_FILE` | Absolute path to a UTF-8 file listing reviewed absolute read paths, one per line. Empty lines are skipped. |

Follow the [reference runtime deployment](../../deploy/reference-runtime/README.md)
for helper, execution identity, storage and Linux enforcement requirements.
The receipt anchor must satisfy the native store's independent-filesystem and
private-directory checks. The read-grants file is operator input, not a script;
its lines are passed as literal `--read-path` arguments. Include the specific
interpreter, shared-library and module paths a dynamic target needs. Prefer the
static reference tools when a Python runtime is unnecessary. Only read grants
are synthesized by these helpers; networked or write-capable tools require an
operator policy that explicitly supports those effects.

With those variables exported on a qualified host, invoke the existing helper:

```bash
source scripts/lib/provision-mcp-launch.sh
chio_provision_mcp_launch "$(command -v chio)" "$PWD/reader-security" \
  reference-reader "Reference Reader" 1 "$PWD" \
  /absolute/path/to/chio-tool-repo-reader --root /absolute/reviewed/repository
```

The helper uses `security provision-reference-runtime --stage enforced` and
confines live tool discovery. It preserves existing signed material and asks
the provisioner to revalidate it on restart. A changed executable or contract
requires deliberate new provisioning; the helper does not delete old authority
or replace it with a weaker launch mode.

The Python `provision_native_demo` helper uses the same configuration and returns
the signed policy path and signer to the process host. Its separate `environment`
argument still controls the provisioning subprocess environment. The operator
configuration is read by the calling Python process before that subprocess runs.

For containers, the helper, grants and anchor paths must exist inside the
container with the required ownership, independent storage and enforcement
support. The Docker example's `enforced-native` profile requires a qualified
host override. The default Compose topology starts the trust service and proof
viewer without attempting an unconfigured native launch.

Argument-builder and rejection tests establish local configuration behavior.
They do not qualify a native host, container confinement, protocol conformance
campaign or secure-swarm deployment. Existing historical demo results do not
substitute for those checks against the current runtime.
