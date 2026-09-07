import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const { ProcessClient } = await import(process.argv[2]);
const bootstrap = JSON.parse(readFileSync(0, "utf8"));
const { socket_path, credential, process_id } = bootstrap.connection;
const client = new ProcessClient(socket_path, credential);
const { configuration, task } = bootstrap.input;
assert.ok(Number.isSafeInteger(task.value));
const save = (name, value) => writeFileSync(join(configuration.directory, name), JSON.stringify(value), { mode: 0o600, flush: true });
save(`${process_id}-${bootstrap.attempt}-started.json`, { pid: process.pid });
const sent = await client.invoke("send-result", "chio-ipc", "send_results", {
  message_key: process_id, payload: { value: task.value },
});
assert.equal(sent.verdict, "allow");
save(`${process_id}-send-${bootstrap.attempt}.json`, sent);
if (configuration.recover && task.value === 2 && bootstrap.attempt === 1) process.exit(76);
for (const [server, tool, args] of [
  ["chio-ipc", "receive_results", { after_sequence: "0", limit: 1 }],
  ["chio-process", "spawn_branch", { input: {}, budget_share_bps: 1 }],
]) {
  const denied = await client.invoke(`denied-${tool}`, server, tool, args);
  assert.equal(denied.verdict, "deny");
  assert.equal(denied.output, null);
  save(`${process_id}-${tool}-${bootstrap.attempt}.json`, denied);
}
