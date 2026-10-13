import { canonicalizeJson, parseJsonTextUniqueKeys } from "./invariants/json.ts";
import { sha256HexUtf8 } from "./invariants/hashing.ts";

export interface ContentRef { ownerDomain: string; artifactId: string; sha256: string; byteLength: number }
export type SchemaShape = { kind: "value"; schema: ContentRef } | { kind: "all_success"; schemas: ContentRef[] };
export type ResourceOperation = "read" | "write" | "invoke";
export interface ResourceRequirement { namespace: string; resourceId: string; ownerDomain: string; generation: number; operations: ResourceOperation[] }
export interface ResourceBinding extends ResourceRequirement { provider: ContentRef; version: { kind: "live" } | { kind: "pinned"; content: ContentRef } }
export interface ComputerRecord { computerId: string; ownerDomain: string; parentRevision: string | null; headRevision: string; lifecycleGeneration: number; profileRefs: ContentRef[] }
export interface ComputerRevision { computerId: string; ownerDomain: string; revisionId: string; namespaceDigest: string; boot: ContentRef; input: ContentRef; inputSchema: SchemaShape; resources: ResourceBinding[]; profileRefs: ContentRef[]; creationOperation: string }
export interface ComputerImage { revisionId: string; boot: ContentRef; input: ContentRef; resourceManifestDigest: string; requirements: ContentRef[] }
export interface ComputerDescription { schema: string; record: ComputerRecord; revision: ComputerRevision; image: ComputerImage }
export type LeafDescriptor = {
  kind: "task"; contract: ContentRef; inputSchema: SchemaShape; outputSchema: ContentRef;
  acceptance: ContentRef; harnessRequirements: ContentRef[]; resources: ResourceRequirement[];
} | { kind: "program"; bundle: ContentRef; entrypoint: string; inputSchema: SchemaShape; outputSchema: ContentRef; resources: ResourceRequirement[] };
export type ProgramDescription = { op: "leaf"; leaf: LeafDescriptor } | { op: "parallel" | "sequence"; items: ProgramDescription[] };
export interface ProgramOccurrence { occurrenceId: string; path: number[]; parents: string[]; leaf: LeafDescriptor }
export interface CompiledDescription {
  schema: string; requestId: string; computerId: string; ownerDomain: string; revisionId: string;
  lifecycleGeneration: number; programDigest: string; expression: ProgramDescription;
  occurrences: ProgramOccurrence[]; outputSchema: SchemaShape; digest: string;
}

export class DescriptionError extends Error {
  readonly code: string;
  constructor(code: string) {
    super(`Computer description rejected: ${code}`);
    this.name = "DescriptionError";
    this.code = code;
  }
}

const MAX_BYTES = 2 * 1024 * 1024;
const MAX_TRANSFER = 64 * 1024 * 1024;
const ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}(?![\s\S])/;
const HASH = /^[0-9a-f]{64}(?![\s\S])/;
function requireValue(value: unknown, code: string): asserts value {
  if (!value) throw new DescriptionError(code);
}
function object(value: unknown, keys: string): asserts value is Record<string, unknown> {
  requireValue(value !== null && typeof value === "object" && !Array.isArray(value), "json_shape");
  const actual = Object.keys(value).sort();
  requireValue(actual.join(" ") === keys.split(" ").sort().join(" "), "json_shape");
}
function array(value: unknown, limit: number, code: string): asserts value is unknown[] {
  requireValue(Array.isArray(value), "json_shape");
  requireValue(value.length <= limit, code);
}
function id(value: unknown): asserts value is string {
  requireValue(typeof value === "string" && ID.test(value), "identifier");
}
function hash(value: unknown): asserts value is string {
  requireValue(typeof value === "string" && HASH.test(value), "digest_format");
}
function generation(value: unknown): asserts value is number {
  requireValue(typeof value === "number" && Number.isSafeInteger(value) && value > 0, "generation");
}
function namespace(value: unknown): asserts value is string {
  requireValue(typeof value === "string" && Buffer.byteLength(value) <= 256 && value.startsWith("/") && value !== "/", "namespace");
  requireValue(value.split("/").slice(1).every(part => ID.test(part) && part !== "." && part !== ".."), "namespace");
}
function content(value: unknown): number {
  object(value, "ownerDomain artifactId sha256 byteLength");
  id(value.ownerDomain); id(value.artifactId); hash(value.sha256);
  const size = value.byteLength;
  requireValue(typeof size === "number" && Number.isSafeInteger(size) && size >= 0 && size <= MAX_TRANSFER, "transfer_bytes");
  return size;
}
function profiles(values: unknown): number {
  array(values, 64, "profiles");
  let total = 0;
  const seen = new Set<string>();
  for (const value of values) {
    total += content(value);
    const ref = value as ContentRef;
    const identity = `${ref.ownerDomain}:${ref.artifactId}`;
    requireValue(!seen.has(identity), "duplicate_profile"); seen.add(identity);
  }
  return total;
}
function shape(value: unknown): number {
  requireValue(value !== null && typeof value === "object", "json_shape");
  if ((value as Record<string, unknown>).kind === "value") {
    object(value, "kind schema"); return content(value.schema);
  }
  object(value, "kind schemas"); requireValue(value.kind === "all_success", "json_shape");
  array(value.schemas, 16, "parent_count"); requireValue(value.schemas.length >= 2, "parent_count");
  return value.schemas.reduce<number>((total, item) => total + content(item), 0);
}
function operations(value: unknown): void {
  array(value, 3, "operations");
  requireValue(value.length > 0 && value.every(item => item === "read" || item === "write" || item === "invoke"), "operations");
  requireValue(new Set(value).size === value.length, "operations");
}
function resources(values: unknown): number {
  array(values, 256, "resource_count");
  let total = 0;
  const seen = new Set<string>();
  for (const value of values) {
    object(value, "namespace resourceId ownerDomain generation provider operations version");
    namespace(value.namespace); requireValue(!seen.has(value.namespace), "duplicate_namespace"); seen.add(value.namespace);
    id(value.resourceId); id(value.ownerDomain); generation(value.generation); operations(value.operations);
    total += content(value.provider);
    const version = value.version;
    requireValue(version !== null && typeof version === "object", "json_shape");
    if ((version as Record<string, unknown>).kind === "live") object(version, "kind");
    else {
      object(version, "kind content"); requireValue(version.kind === "pinned", "json_shape"); total += content(version.content);
    }
  }
  return total;
}
function digest(domain: string, body: unknown): string { return sha256HexUtf8(canonicalizeJson({ domain, body })); }
function wireBound(value: unknown, bound: number): void {
  const pending = [value]; let size = 0;
  while (pending.length) {
    const item = pending.pop();
    if (item !== null && typeof item === "object") {
      const values = Array.isArray(item) ? item : Object.values(item);
      size += 2 + Math.max(0, values.length - 1);
      if (!Array.isArray(item)) {
        for (const key of Object.keys(item)) size += Buffer.byteLength(JSON.stringify(key)) + 1;
      }
      for (const entry of values) pending.push(entry);
    } else {
      const encoded = JSON.stringify(item);
      requireValue(encoded !== undefined, "json_shape"); size += Buffer.byteLength(encoded);
    }
    requireValue(size <= bound, "wire_bytes");
  }
}
function equal(left: unknown, right: unknown): boolean { return canonicalizeJson(left) === canonicalizeJson(right); }
export function namespaceDigest(values: ResourceBinding[]): string {
  requireValue(resources(values) <= MAX_TRANSFER, "transfer_bytes"); return digest("chio.computer.namespace.v1", values);
}
function revisionFields(value: unknown): number {
  object(value, "computerId ownerDomain revisionId namespaceDigest boot input inputSchema resources profileRefs creationOperation");
  id(value.computerId); id(value.ownerDomain); id(value.creationOperation); hash(value.namespaceDigest);
  return content(value.boot) + content(value.input) + shape(value.inputSchema) + profiles(value.profileRefs) + resources(value.resources);
}
export function revisionDigest(revision: ComputerRevision): string {
  requireValue(revisionFields(revision) <= MAX_TRANSFER, "transfer_bytes");
  if (revision.revisionId !== "") hash(revision.revisionId);
  const { revisionId: _revisionId, ...body } = revision;
  return digest("chio.computer.revision.v1", body);
}
export function validateComputer(value: unknown): number {
  object(value, "schema record revision image"); requireValue(value.schema === "chio.computer.description.v1", "description_schema");
  const { record, revision, image } = value;
  object(record, "computerId ownerDomain parentRevision headRevision lifecycleGeneration profileRefs");
  object(image, "revisionId boot input resourceManifestDigest requirements");
  id(record.computerId); id(record.ownerDomain); generation(record.lifecycleGeneration); hash(record.headRevision);
  if (record.parentRevision !== null) hash(record.parentRevision);
  let total = profiles(record.profileRefs) + revisionFields(revision);
  const r = revision as ComputerRevision;
  hash(r.revisionId); hash(image.revisionId); hash(image.resourceManifestDigest);
  total += content(image.boot) + content(image.input) + profiles(image.requirements);
  requireValue(total <= MAX_TRANSFER, "transfer_bytes");
  requireValue(record.computerId === r.computerId && record.ownerDomain === r.ownerDomain && record.headRevision === r.revisionId
    && equal(record.profileRefs, r.profileRefs) && image.revisionId === r.revisionId && equal(image.boot, r.boot)
    && equal(image.input, r.input) && image.resourceManifestDigest === r.namespaceDigest, "revision_binding");
  requireValue((image.requirements as ContentRef[]).every(profile => r.profileRefs.some(candidate => equal(profile, candidate))), "profile_subset");
  requireValue(r.namespaceDigest === namespaceDigest(r.resources), "namespace_digest");
  requireValue(r.revisionId === revisionDigest(r), "revision_digest");
  return total;
}
function integerToken(token: string): string {
  requireValue(token.length <= 1024, "json_number");
  const match = /^(-?)(0|[1-9][0-9]*)(?:\.([0-9]+))?(?:[eE]([+-]?[0-9]+))?(?![\s\S])/.exec(token);
  requireValue(match !== null, "json_shape");
  const fraction = match[3] ?? "";
  let digits = (match[2] + fraction).replace(/^0+/, "");
  if (!digits) return "0";
  requireValue(!match[1], "json_number");
  const exponent = match[4] ?? "0";
  requireValue(exponent.replace(/^[+-]?0*/, "").length <= 4, "json_number");
  const power = Number(exponent) - fraction.length;
  if (power < 0) {
    requireValue(-power <= digits.length && digits.slice(power) === "0".repeat(-power), "json_number");
    digits = digits.slice(0, power);
  } else {
    requireValue(digits.length + power <= 16, "json_number");
    digits += "0".repeat(power);
  }
  requireValue(digits.length <= 16 && (digits.length < 16 || digits <= "9007199254740991"), "json_number");
  return digits;
}
function normalizeNumbers(text: string, bound: number): string {
  const result = text.replace(/"(?:[^"\\]|\\.)*"|-?[0-9][0-9.eE+\-]*/g, token => token.startsWith('"') ? token : integerToken(token));
  requireValue(Buffer.byteLength(result) <= bound, "wire_bytes");
  return result;
}
function utf8Size(value: string): number {
  requireValue(!/[\uD800-\uDFFF]/u.test(value), "json_shape");
  return Buffer.byteLength(value);
}
function parseBounded(text: string, bound: number, entryLimit: number): unknown {
  requireValue(typeof text === "string", "json_shape");
  requireValue(utf8Size(text) <= bound, "wire_bytes");
  let depth = 0, quoted = false, escaped = false;
  for (const char of text) {
    if (quoted) {
      if (escaped) escaped = false;
      else if (char === "\\") escaped = true;
      else if (char === '"') quoted = false;
    } else if (char === '"') quoted = true;
    else if (char === "[" || char === "{") { depth++; requireValue(depth <= 96, "json_depth"); }
    else if (char === "]" || char === "}") depth--;
  }
  let value: unknown;
  try { value = parseJsonTextUniqueKeys(normalizeNumbers(text, bound)); }
  catch (error) { if (error instanceof DescriptionError) throw error; throw new DescriptionError("json_shape"); }
  const pending = [value]; let entries = 0;
  while (pending.length) {
    const item = pending.pop();
    if (typeof item === "string") requireValue(utf8Size(item) <= 1024, "string_bytes");
    else if (item !== null && typeof item === "object") {
      const values = Array.isArray(item) ? item : Object.values(item);
      entries += values.length; requireValue(entries <= entryLimit, "json_entries");
      if (!Array.isArray(item)) requireValue(Object.keys(item).every(key => utf8Size(key) <= 1024), "string_bytes");
      for (const entry of values) pending.push(entry);
    }
  }
  return value;
}
export function parseDescription(text: string): unknown { return parseBounded(text, MAX_BYTES, 65536); }
export function parseCompiledDescription(text: string): unknown { return parseBounded(text, 8 * 1024 * 1024, 262144); }
export class ProgramExpr {
  readonly description: ProgramDescription;
  constructor(description: ProgramDescription) { this.description = description; }
  static leaf(leaf: LeafDescriptor): ProgramExpr { return new ProgramExpr({ op: "leaf", leaf }); }
  pipe(other: ProgramExpr): ProgramExpr { return new ProgramExpr({ op: "sequence", items: [this.description, other.description] }); }
}
export function parallel(...items: ProgramExpr[]): ProgramExpr { return new ProgramExpr({ op: "parallel", items: items.map(item => item.description) }); }
function leaf(value: unknown): number {
  requireValue(value !== null && typeof value === "object", "json_shape");
  let total;
  if ((value as Record<string, unknown>).kind === "task") {
    object(value, "kind contract inputSchema outputSchema acceptance harnessRequirements resources");
    total = content(value.contract) + content(value.acceptance) + profiles(value.harnessRequirements);
    requireValue((value.harnessRequirements as ContentRef[]).length > 0, "harness_requirements");
  } else {
    object(value, "kind bundle entrypoint inputSchema outputSchema resources"); requireValue(value.kind === "program", "json_shape");
    total = content(value.bundle); id(value.entrypoint);
  }
  total += shape(value.inputSchema) + content(value.outputSchema);
  array(value.resources, 256, "resource_count"); const seen = new Set<string>();
  for (const resource of value.resources) {
    object(resource, "namespace resourceId ownerDomain generation operations"); namespace(resource.namespace);
    requireValue(!seen.has(resource.namespace), "duplicate_namespace"); seen.add(resource.namespace);
    id(resource.resourceId); id(resource.ownerDomain); generation(resource.generation); operations(resource.operations);
  }
  return total;
}
function preflight(expression: unknown): number {
  const pending: [unknown, number][] = [[expression, 1]]; let nodes = 0, leaves = 0, total = 0;
  while (pending.length) {
    const entry = pending.pop(); if (!entry) throw new DescriptionError("json_shape");
    const [item, depth] = entry;
    nodes++; requireValue(nodes <= 2047, "expression_nodes"); requireValue(depth <= 32, "expression_depth");
    requireValue(item !== null && typeof item === "object", "json_shape");
    if ((item as Record<string, unknown>).op === "leaf") {
      object(item, "op leaf"); leaves++; requireValue(leaves <= 1024, "leaf_count");
      total += leaf(item.leaf); requireValue(total <= MAX_TRANSFER, "transfer_bytes");
    } else {
      object(item, "op items"); requireValue(item.op === "parallel" || item.op === "sequence", "json_shape");
      array(item.items, 2047, "expression_nodes"); requireValue(item.items.length >= 2 && nodes + pending.length + item.items.length <= 2047, "expression_nodes");
      for (const child of [...item.items].reverse()) pending.push([child, depth + 1]);
    }
  }
  return total;
}
function normalize(expression: ProgramDescription): ProgramDescription {
  if (expression.op === "leaf") return structuredClone(expression);
  const items: ProgramDescription[] = [];
  for (const child of expression.items) {
    const normalized = normalize(child);
    if (normalized.op !== "leaf" && normalized.op === expression.op) items.push(...normalized.items);
    else items.push(normalized);
  }
  return { op: expression.op, items };
}
export function compileProgram(computerValue: unknown, requestId: string, expressionValue: unknown | ProgramExpr): CompiledDescription {
  const raw = expressionValue instanceof ProgramExpr ? expressionValue.description : expressionValue;
  id(requestId); const total = preflight(raw);
  requireValue(validateComputer(computerValue) + total <= MAX_TRANSFER, "transfer_bytes");
  wireBound([computerValue, requestId, raw], MAX_BYTES);
  const computer = computerValue as ComputerDescription;
  const expression = normalize(raw as ProgramDescription), programDigest = digest("chio.computer.program.v1", expression);
  const occurrences: ProgramOccurrence[] = []; let edges = 0;
  function walk(item: ProgramDescription, path: number[], input: SchemaShape, parents: string[]): [SchemaShape, string[]] {
    if (item.op === "leaf") {
      requireValue(equal(item.leaf.inputSchema, input), "input_schema"); requireValue(parents.length <= 16, "parent_count");
      edges += parents.length; requireValue(edges <= 4096, "dependency_edges");
      for (const required of item.leaf.resources) {
        const binding = computer.revision.resources.find(candidate => candidate.namespace === required.namespace);
        requireValue(binding && binding.resourceId === required.resourceId && binding.ownerDomain === required.ownerDomain
          && binding.generation === required.generation && required.operations.every(operation => binding.operations.includes(operation)), "resource_subset");
      }
      const occurrenceId = digest("chio.computer.occurrence.v1", { requestId, computerId: computer.record.computerId,
        ownerDomain: computer.record.ownerDomain, revisionId: computer.revision.revisionId, programDigest, path });
      occurrences.push({ occurrenceId, path, parents: [...parents], leaf: structuredClone(item.leaf) });
      return [{ kind: "value", schema: structuredClone(item.leaf.outputSchema) }, [occurrenceId]];
    }
    if (item.op === "parallel") {
      const schemas: ContentRef[] = [], outputs: string[] = [];
      for (const [index, child] of item.items.entries()) {
        const [shape, terminal] = walk(child, [...path, index], input, parents);
        schemas.push(...(shape.kind === "value" ? [shape.schema] : shape.schemas)); outputs.push(...terminal);
        requireValue(schemas.length <= 16, "parent_count");
      }
      return [{ kind: "all_success", schemas }, outputs];
    }
    let shape = input, terminal = parents;
    for (const [index, child] of item.items.entries()) [shape, terminal] = walk(child, [...path, index], shape, terminal);
    return [shape, terminal];
  }
  const [outputSchema] = walk(expression, [], computer.revision.inputSchema, []);
  const body = { schema: "chio.computer.compiled-description.v1", requestId, computerId: computer.record.computerId,
    ownerDomain: computer.record.ownerDomain, revisionId: computer.revision.revisionId, lifecycleGeneration: computer.record.lifecycleGeneration,
    programDigest, expression, occurrences, outputSchema };
  const result = { ...body, digest: digest("chio.computer.compiled.v1", body) };
  wireBound(result, 8 * 1024 * 1024); return result;
}
export function validateCompiledProgram(computer: unknown, requestId: string, expression: unknown | ProgramExpr, value: unknown): CompiledDescription {
  object(value, "schema requestId computerId ownerDomain revisionId lifecycleGeneration programDigest expression occurrences outputSchema digest");
  requireValue(value.schema === "chio.computer.compiled-description.v1", "description_schema");
  id(value.requestId); id(value.computerId); id(value.ownerDomain);
  hash(value.revisionId); hash(value.programDigest); hash(value.digest); generation(value.lifecycleGeneration);
  requireValue(shape(value.outputSchema) <= MAX_TRANSFER, "transfer_bytes");
  preflight(value.expression); array(value.occurrences, 1024, "leaf_count");
  let total = 0;
  for (const occurrence of value.occurrences) {
    object(occurrence, "occurrenceId path parents leaf"); array(occurrence.path, 32, "plan_bounds"); array(occurrence.parents, 16, "plan_bounds");
    hash(occurrence.occurrenceId);
    requireValue(occurrence.path.every(index => typeof index === "number" && Number.isInteger(index) && index >= 0 && index < 2047), "plan_bounds");
    for (const parent of occurrence.parents) hash(parent);
    total += leaf(occurrence.leaf); requireValue(total <= MAX_TRANSFER, "transfer_bytes");
  }
  wireBound(value, 8 * 1024 * 1024);
  const result = compileProgram(computer, requestId, expression);
  requireValue(equal(result, value), "compiled_mismatch"); return result;
}
