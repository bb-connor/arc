import { createHash } from "node:crypto";
import type { Json, ProcessClient } from "@chio-protocol/process";
import { ModelJournalError } from "./model-codec.js";

export type BlobClient = Partial<Pick<ProcessClient, "putBlob" | "readBlob">>;
// Arrays keep the reference hash stable through a native JSON object reorder.
export type ResponseBlobs = ["chio.ai-sdk.response.v1", number, string, [string, number][]];
const CHUNK_BYTES = 1_048_576;
const hash = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest("hex");
const validHash = (value: unknown): value is string => typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
const invalid = () => new ModelJournalError("model_checkpoint_invalid");

export function validateBlobs(value: unknown, maxBytes: number): asserts value is ResponseBlobs {
  if (!Array.isArray(value) || value.length !== 4 || value[0] !== "chio.ai-sdk.response.v1" ||
      !Number.isSafeInteger(value[1]) || value[1] < 1 || value[1] > maxBytes || !validHash(value[2]) ||
      !Array.isArray(value[3]) || value[3].length !== Math.ceil(value[1] / CHUNK_BYTES)) throw invalid();
  let bytes = 0;
  for (const [index, chunk] of value[3].entries()) {
    const expected = Math.min(CHUNK_BYTES, value[1] - index * CHUNK_BYTES);
    if (!Array.isArray(chunk) || chunk.length !== 2 || !validHash(chunk[0]) || chunk[1] !== expected) throw invalid();
    bytes += chunk[1];
  }
  if (bytes !== value[1]) throw invalid();
}

export async function saveBlobs(client: BlobClient, bytes: Buffer): Promise<ResponseBlobs> {
  if (!client.putBlob) throw new ModelJournalError("model_storage_unavailable");
  const chunks: [string, number][] = [];
  for (let offset = 0; offset < bytes.length; offset += CHUNK_BYTES) {
    const chunk = bytes.subarray(offset, offset + CHUNK_BYTES), sha256 = hash(chunk);
    const reference = await client.putBlob(new Uint8Array(chunk));
    if (reference.sha256 !== sha256 || reference.bytes !== chunk.length) throw invalid();
    chunks.push([sha256, chunk.length]);
  }
  return ["chio.ai-sdk.response.v1", bytes.length, hash(bytes), chunks];
}

export async function loadBlobs(client: BlobClient, reference: ResponseBlobs, maxBytes: number): Promise<Json> {
  validateBlobs(reference, maxBytes);
  if (!client.readBlob) throw new ModelJournalError("model_storage_unavailable");
  const chunks: Buffer[] = [];
  for (const [sha256, size] of reference[3]) {
    const bytes = await client.readBlob(sha256);
    if (!(bytes instanceof Uint8Array) || bytes.length !== size || hash(bytes) !== sha256) throw invalid();
    chunks.push(Buffer.from(bytes));
  }
  const bytes = Buffer.concat(chunks);
  if (bytes.length !== reference[1] || hash(bytes) !== reference[2]) throw invalid();
  try { return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)) as Json; }
  catch { throw invalid(); }
}
