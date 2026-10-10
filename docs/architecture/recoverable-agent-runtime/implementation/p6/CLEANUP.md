# Task resource cleanup

Fresh OCI readback confirms the exact tagged task instance and boot volume are
TERMINATED, all eight task session records are DELETED, the captured task console
history returns not found, and only the three task-added /32 CIDRs were removed.
The original bastion CIDR remains. No matching task SSH tunnel remains; its
private key was removed after matching the registered public key.

The shared predecessor qualification VM was already RUNNING before this cleanup
and remains RUNNING with identical agent configuration. It was not stopped,
terminated or reconfigured. Unrelated Mac workloads were preserved.

[Exact readbacks and limits](evidence/owned-resource-cleanup.json) retain ownership,
terminal states and scope. Historical command metadata is retained; no definitive
execution-terminal proof is claimed for the earlier shared-host read-only
preflight. The task VM and boot volume are terminated.
