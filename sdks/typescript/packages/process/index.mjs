import { createHash } from "node:crypto";
import { createConnection } from "node:net";

export const PROTOCOL = "chio.process.v1";
export const MAX_REQUEST_BYTES = 2 * 1024 * 1024;
export const STATE_BLOB_PROTOCOL = "chio.process.blobs.v1";
export const MAX_STATE_BLOB_BYTES = 1024 * 1024;
const hash = bytes => createHash("sha256").update(bytes).digest("hex");
const validHash = value => typeof value === "string" && /^[a-f0-9]{64}$/.test(value);

export const MAX_RESPONSE_BYTES = 8 * 1024 * 1024;

export class WorkerError extends Error {
  constructor(code) {
    super(`Chio worker: ${code}`);
    this.name = "WorkerError";
    this.code = code;
  }
}

/** One process. A transport failure can follow a committed effect.
 * Retry the original operation key and identical arguments; never change the
 * key to work around an uncertain outcome. Receipts are returned unverified.
 */
export class ProcessClient {
  #socketPath;
  #credential;
  #timeout;

  constructor(socketPath, credential, { timeoutMs = 60_000 } = {}) {
    if (!Number.isFinite(timeoutMs) || timeoutMs <= 0 || timeoutMs > 2_147_483_647) {
      throw new TypeError("timeoutMs must be positive and fit a Node timer");
    }
    this.#socketPath = socketPath;
    this.#credential = credential;
    this.#timeout = timeoutMs;
  }

  inspect() { return this.#call({ op: "inspect" }); }

  invoke(operationKey, serverId, toolName, args) {
    return this.#call({ op: "invoke", operation_key: operationKey,
      server_id: serverId, tool_name: toolName, arguments: args });
  }

  checkpoint(expectedRevision, value) {
    return this.#call({ op: "checkpoint", expected_revision: expectedRevision, value });
  }

  async putBlob(value) {
    if (!(value instanceof Uint8Array) || value.byteLength > MAX_STATE_BLOB_BYTES) throw new TypeError("Invalid state blob");
    const bytes = Buffer.from(value);
    const sha256 = hash(bytes);
    const result = await this.#call({ op: "blob_put", sha256, data_base64: bytes.toString("base64") });
    if (result.sha256 !== sha256 || result.bytes !== bytes.length) throw new WorkerError("invalid_response");
    return { sha256, bytes: bytes.length };
  }

  async readBlob(sha256) {
    if (!validHash(sha256)) throw new TypeError("Invalid state blob digest");
    const result = await this.#call({ op: "blob_read", sha256 });
    if (result.sha256 !== sha256 || !Number.isInteger(result.bytes) || result.bytes < 0 || result.bytes > MAX_STATE_BLOB_BYTES ||
        typeof result.data_base64 !== "string" || result.data_base64.length > Math.ceil(MAX_STATE_BLOB_BYTES / 3) * 4) throw new WorkerError("invalid_response");
    const bytes = Buffer.from(result.data_base64, "base64");
    if (bytes.length !== result.bytes || bytes.toString("base64") !== result.data_base64 || hash(bytes) !== sha256) throw new WorkerError("invalid_response");
    return new Uint8Array(bytes);
  }

  cancel() { return this.#call({ op: "cancel" }); }

  async #call(operation) {
    const frame = Buffer.from(JSON.stringify({ protocol: PROTOCOL,
      credential: this.#credential, operation }, (_key, value) => {
      if (typeof value === "number" && (!Number.isFinite(value) ||
          (Number.isInteger(value) && !Number.isSafeInteger(value)))) {
        throw new TypeError("JSON numbers must be finite; encode large integers as strings");
      }
      return value;
    }) + "\n");
    if (frame.length > MAX_REQUEST_BYTES) throw new WorkerError("request_too_large");
    return new Promise((resolve, reject) => {
      const socket = createConnection({ path: this.#socketPath });
      const chunks = [];
      let size = 0;
      let done = false;
      const finish = (error, value) => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        socket.destroy();
        if (error) reject(error); else resolve(value);
      };
      // Absolute deadline; trickling response bytes cannot extend it forever.
      const timer = setTimeout(() => finish(new WorkerError("transport_error")), this.#timeout);
      socket.once("connect", () => socket.write(frame));
      socket.on("error", () => finish(new WorkerError("transport_error")));
      socket.once("close", () => finish(new WorkerError("truncated_response")));
      socket.on("data", (chunk) => {
        if (done) return;
        const end = chunk.indexOf(10);
        const part = end < 0 ? chunk : chunk.subarray(0, end + 1);
        size += part.length;
        if (size > MAX_RESPONSE_BYTES) return finish(new WorkerError("response_too_large"));
        chunks.push(part);
        if (end < 0) return;
        let decoded;
        try {
          const text = new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks, size));
          decoded = JSON.parse(text);
        } catch { return finish(new WorkerError("invalid_response")); }
        if (decoded?.protocol !== PROTOCOL) return finish(new WorkerError("invalid_response"));
        if (decoded.ok === false && typeof decoded.error?.code === "string") {
          return finish(new WorkerError(decoded.error.code));
        }
        if (decoded.ok !== true || !decoded.result || typeof decoded.result !== "object" ||
            Array.isArray(decoded.result)) return finish(new WorkerError("invalid_response"));
        finish(null, decoded.result);
      });
    });
  }
}
