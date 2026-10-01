import { readFileSync } from "node:fs";
import { ProcessClient } from "../../../../../sdks/typescript/packages/process/index.mjs";

// Deterministic source inventory worker; no model or network credentials.
const config = JSON.parse(readFileSync(0, "utf8"));
const client = new ProcessClient(config.socket_path, config.credential);
const read = await client.invoke("read-snapshot", "tools", "read", {});
if (read.verdict !== "allow") throw new Error("source snapshot denied");
const files = read.output.value.files;
const report = {
  worker: "javascript",
  files: files.length,
  nonempty_lines: files.reduce((sum, file) => sum + file.content.split("\n").filter(line => line.trim()).length, 0),
  paths: files.map(file => file.path).sort(),
};
const published = await client.invoke("publish-inventory", "tools", "append", report);
if (published.verdict !== "allow") throw new Error("inventory publication denied");
const snapshot = await client.inspect();
const bytes = Uint8Array.from({ length: 1_048_576 }, (_, index) => index % 256);
if (snapshot.checkpoint.revision === "0") {
  const blob = await client.putBlob(bytes);
  await client.checkpoint("0", { published: true, blob });
}
const reference = (await client.inspect()).checkpoint.value.blob;
const stored = await client.readBlob(reference.sha256);
if (stored.length !== bytes.length || stored.some((byte, index) => byte !== bytes[index])) throw new Error("persisted blob differs");
console.log(JSON.stringify({ read, published, snapshot: await client.inspect() }));
