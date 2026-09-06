import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { performance } from "node:perf_hooks";
import { DatabaseSync } from "node:sqlite";
import { generateText, stepCountIs, tool, jsonSchema } from "ai";
import { createOpenAICompatible } from "@ai-sdk/openai-compatible";

process.umask(0o077);
const settings = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
const attempt = Number(process.argv[3]);
const directory = settings.directory;

function persist(name, value) {
  const target = path.join(directory, name), temporary = target + ".tmp";
  const fd = fs.openSync(temporary, "w", 0o600);
  try { fs.writeFileSync(fd, JSON.stringify(value)); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  fs.renameSync(temporary, target);
  const parent = fs.openSync(directory, "r");
  try { fs.fsyncSync(parent); } finally { fs.closeSync(parent); }
}
function append(name, value) {
  const fd = fs.openSync(path.join(directory, name), "a", 0o600);
  try { fs.writeSync(fd, JSON.stringify(value) + "\n"); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
}

persist(`started-${attempt}.json`, { pid: process.pid, attempt, at: Date.now() });
const db = new DatabaseSync(settings.database);
db.exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
  CREATE TABLE IF NOT EXISTS reads(id INTEGER PRIMARY KEY, file_index INTEGER NOT NULL);
  CREATE TABLE IF NOT EXISTS reports(id INTEGER PRIMARY KEY, report TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS messages(id INTEGER PRIMARY KEY, channel TEXT NOT NULL, message_key TEXT NOT NULL, payload TEXT NOT NULL, acked INTEGER NOT NULL DEFAULT 0);
  CREATE TABLE IF NOT EXISTS timings(id INTEGER PRIMARY KEY, path TEXT NOT NULL, tool TEXT NOT NULL, duration_ms REAL NOT NULL);`);
const timing = db.prepare("INSERT INTO timings(path,tool,duration_ms) VALUES('local',?,?)");

const seen = new Map();
let calls = 0;
function timed(role, name, execute) {
  return async input => {
    const started = performance.now();
    const value = await execute(input);
    const ms = performance.now() - started;
    timing.run(name, ms);
    append("calls.ndjson", { role, attempt, tool: name, ms, at: Date.now() });
    if (++calls === 1) persist(`first-call-${attempt}.json`, { at: Date.now() });
    const key = `${role}:${name}`;
    seen.set(key, (seen.get(key) ?? 0) + 1);
    const kill = settings.kill;
    if (kill && kill.role === role && kill.attempt === attempt && kill.tool === name && seen.get(key) === (kill.ordinal ?? 1)) {
      persist(`killed-${attempt}.json`, { role, tool: name, ordinal: seen.get(key) });
      process.exit(77);
    }
    return value;
  };
}
const schema = (properties, required) => jsonSchema({ type: "object", properties, required, additionalProperties: false });
const publishTool = role => tool({ description: "Append one checked report", inputSchema: schema({ report: { type: "string" } }, ["report"]),
  execute: timed(role, "publish", async ({ report }) => {
    const value = { report_id: Number(db.prepare("INSERT INTO reports(report) VALUES(?)").run(report).lastInsertRowid) };
    return { content: [{ type: "text", text: JSON.stringify(value) }], structuredContent: value };
  }) });
const readTool = role => tool({ description: "Read one 8 KiB source file",
  inputSchema: schema({ index: { type: "integer", minimum: 1, maximum: 16 }, path: { type: "string", enum: settings.sources } }, ["index", "path"]),
  execute: timed(role, "read", async ({ index, path: source }) => {
    assert.equal(source, settings.sources[index - 1]);
    const text = fs.readFileSync(source, "utf8");
    db.prepare("INSERT INTO reads(file_index) VALUES(?)").run(index);
    return { content: [{ type: "text", text }], structuredContent: { index } };
  }) });

const provider = createOpenAICompatible({ name: "research-swarm", baseURL: settings.endpoint });
const children = new Map();

async function researcher(index, paths) {
  const role = `researcher-${index}`;
  const tools = {
    sources__read: readTool(role),
    "chio-ipc__send_findings": tool({ description: "Send findings to the coordinator",
      inputSchema: schema({ message_key: { type: "string" }, payload: {} }, ["message_key", "payload"]),
      execute: timed(role, "send_findings", async ({ message_key, payload }) => {
        const row = db.prepare("INSERT INTO messages(channel,message_key,payload) VALUES('findings',?,?)").run(message_key, JSON.stringify(payload));
        return { status: "sent", sequence: String(row.lastInsertRowid) };
      }) }),
  };
  if (settings.mode === "conflict" && index === 1) tools.report__publish = publishTool(role);
  const result = await generateText({ model: provider.chatModel(role), tools, maxRetries: 0, stopWhen: stepCountIs(10),
    prompt: JSON.stringify({ instruction: "Read each assigned source and send your findings.", task: { index, paths } }) });
  assert.equal(result.text, "Findings sent.");
}

const coordinatorTools = {
  // Offered for planner parity with the native coordinator's delegable read route.
  sources__read: readTool("coordinator"),
  "chio-process__spawn_researcher": tool({ description: "Start child work with this configured template and narrower authority.",
    inputSchema: schema({ input: {}, budget_share_bps: { type: "integer" } }, ["input", "budget_share_bps"]),
    execute: timed("coordinator", "spawn_researcher", async ({ input }) => {
      const id = `researcher-${input.index}`;
      const running = researcher(input.index, input.paths);
      running.catch(() => {});
      children.set(id, running);
      return { process: id };
    }) }),
  "chio-process__wait_children": tool({ description: "Join direct children.", inputSchema: schema({ children: { type: "array", items: { type: "string" } } }, ["children"]),
    execute: timed("coordinator", "wait_children", async ({ children: ids }) => {
      if ((settings.hang ?? []).some(spec => spec.role === "coordinator" && spec.attempt === attempt)) {
        // Hold the join open once a handoff exists so the harness can interrupt mid-run.
        while (db.prepare("SELECT count(*) AS n FROM messages").get().n === 0) await new Promise(resolve => setTimeout(resolve, 20));
        persist("hang-coordinator.json", { pid: process.pid, suspended: true });
        await new Promise(() => { setInterval(() => {}, 1000); });
      }
      await Promise.all(ids.map(id => children.get(id)));
      return { complete: true, children: ids };
    }) }),
  "chio-ipc__receive_findings": tool({ description: "Read pending findings", inputSchema: schema({ after_sequence: { type: "string" }, limit: { type: "integer" } }, ["after_sequence", "limit"]),
    execute: timed("coordinator", "receive_findings", async ({ after_sequence, limit }) => {
      const rows = db.prepare("SELECT id, payload FROM messages WHERE channel='findings' AND acked=0 AND id>? ORDER BY id LIMIT ?").all(Number(after_sequence), limit);
      const messages = rows.map(row => ({ sequence: String(row.id), payload: JSON.parse(row.payload) }));
      return { status: "received", messages, next_sequence: String(rows.length ? rows[rows.length - 1].id : Number(after_sequence)) };
    }) }),
  "chio-ipc__ack_findings": tool({ description: "Acknowledge findings", inputSchema: schema({ through_sequence: { type: "string" } }, ["through_sequence"]),
    execute: timed("coordinator", "ack_findings", async ({ through_sequence }) => {
      db.prepare("UPDATE messages SET acked=1 WHERE channel='findings' AND id<=?").run(Number(through_sequence));
      return { status: "acknowledged", through_sequence };
    }) }),
  report__publish: publishTool("coordinator"),
};

try {
  const result = await generateText({ model: provider.chatModel("coordinator"), tools: coordinatorTools, maxRetries: 0, stopWhen: stepCountIs(12),
    prompt: JSON.stringify({ instruction: "Delegate the sources to researchers, join them, collect their findings and publish one checked report.", task: { role: "coordinator" } }) });
  assert.equal(result.text, "Published the checked report.");
  persist("result.json", { text: result.text, attempt });
} catch (error) {
  persist(`failure-${attempt}.json`, { code: error.code ?? error.name, message: String(error.message).slice(0, 200) });
  process.exitCode = 2;
}
