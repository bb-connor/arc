// Checks the client against spec/fixtures/chio-process-v1.json, the shared
// chio.process.v1 conformance corpus that the Rust worker and the Python
// client also consume.
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
  ProcessClient, WorkerError, PROTOCOL, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, MAX_STATE_BLOB_BYTES,
} from "../index.mjs";

/** CHIO_PROCESS_PROTOCOL_CORPUS, else the source tree holding these tests. */
function locateCorpus() {
  if (process.env.CHIO_PROCESS_PROTOCOL_CORPUS) return process.env.CHIO_PROCESS_PROTOCOL_CORPUS;
  for (let directory = dirname(fileURLToPath(import.meta.url)); ; directory = dirname(directory)) {
    const candidate = join(directory, "spec/fixtures/chio-process-v1.json");
    if (existsSync(candidate)) return candidate;
    if (dirname(directory) === directory) return undefined;
  }
}

const corpusPath = locateCorpus();
const corpus = corpusPath === undefined ? undefined : JSON.parse(readFileSync(corpusPath, "utf8"));
const marker = corpus?.fill_marker;
const credential = corpus?.fixture_credential;

function filled(value, fill) {
  if (fill === undefined) return value;
  if (typeof value === "string") return value.replaceAll(marker, fill.char.repeat(fill.count));
  if (Array.isArray(value)) return value.map(item => filled(item, fill));
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, filled(item, fill)]));
  }
  return value;
}

async function call(client, spec) {
  switch (spec.op) {
    case "inspect": return client.inspect();
    case "invoke": {
      const options = {};
      if ("known_outcome_only" in spec) options.knownOutcomeOnly = spec.known_outcome_only;
      if ("governed_intent" in spec) options.governedIntent = spec.governed_intent;
      return client.invoke(spec.operation_key, spec.server_id, spec.tool_name, spec.arguments, options);
    }
    case "prepare_invocation":
      return client.prepareInvocation(spec.operation_key, spec.server_id, spec.tool_name, spec.arguments);
    case "checkpoint": return client.checkpoint(spec.expected_revision, spec.value);
    case "blob_put": return client.putBlob(new Uint8Array(Buffer.from(spec.data_hex, "hex")));
    case "blob_read": return { data_hex: Buffer.from(await client.readBlob(spec.sha256)).toString("hex") };
    case "cancel": return client.cancel();
    default: throw new Error(`unknown corpus operation ${spec.op}`);
  }
}

function responseBytes(entry) {
  if (entry.response_base64 !== undefined) return Buffer.from(entry.response_base64, "base64");
  return Buffer.from(filled(entry.response, entry.fill), "utf8");
}

/** Accept one connection, record its request line and reply with fixed bytes. */
async function withStubHost(response, run) {
  const directory = await mkdtemp(join(tmpdir(), "chio-js-"));
  const path = join(directory, "s");
  const requests = [];
  const sockets = new Set();
  const server = createServer(socket => {
    sockets.add(socket);
    const chunks = [];
    socket.on("error", () => {});
    socket.on("data", chunk => {
      chunks.push(chunk);
      if (!chunk.includes(10)) return;
      requests.push(Buffer.concat(chunks));
      socket.end(response);
    });
  });
  await new Promise((resolve, reject) => { server.once("error", reject); server.listen(path, resolve); });
  try {
    await run(new ProcessClient(path, credential, { timeoutMs: 10_000 }));
  } finally {
    for (const socket of sockets) socket.destroy();
    await new Promise(resolve => server.close(resolve));
    await rm(directory, { recursive: true, force: true });
  }
  return requests;
}

async function checkOutcome(entry, operation) {
  if (entry.error === "invalid_argument") {
    await assert.rejects(operation(), TypeError);
  } else if (entry.error !== undefined) {
    await assert.rejects(operation(), error => error instanceof WorkerError && error.code === entry.error);
  } else if (entry.result !== undefined) {
    assert.deepEqual(await operation(), entry.result);
  } else {
    assert.equal(entry.accepted, true);
    assert.equal(typeof await operation(), "object");
  }
}

if (corpus === undefined) {
  test("shared protocol corpus", { skip: "the shared corpus is outside this copy of the tests" }, () => {});
}

test("limits and identifiers match the corpus", { skip: corpus === undefined }, () => {
  assert.equal(PROTOCOL, corpus.protocol);
  assert.equal(MAX_REQUEST_BYTES, corpus.limits.max_request_bytes);
  assert.equal(MAX_RESPONSE_BYTES, corpus.limits.max_response_bytes);
  assert.equal(MAX_STATE_BLOB_BYTES, corpus.limits.max_state_blob_bytes);
});

for (const entry of corpus?.client.cases ?? []) {
  test(`corpus client case ${entry.name}`, async () => {
    const spec = filled(entry.call, entry.fill);
    if (entry.sent === false) {
      // A client that tried to connect would report transport_error instead.
      await checkOutcome(entry, () => call(new ProcessClient("/absent", credential), spec));
      return;
    }
    const requests = await withStubHost(responseBytes(entry), client => checkOutcome(entry, () => call(client, spec)));
    assert.equal(requests.length, 1);
    const [sent] = requests;
    if (entry.request !== undefined) assert.equal(sent.toString("utf8"), filled(entry.request, entry.fill));
    assert.equal(sent.at(-1), 10);
    assert.equal(sent.indexOf(10), sent.length - 1);
    assert(sent.length <= corpus.limits.max_request_bytes);
  });
}
