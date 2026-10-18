import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { DescriptionError, ProgramExpr, compileProgram, namespaceDigest, revisionDigest, parallel, parseCompiledDescription, parseDescription, validateCompiledProgram } from "../src/computer.ts";
import { canonicalizeJson } from "../src/invariants/json.ts";

const fixture = JSON.parse(readFileSync(new URL("../../../../tests/bindings/vectors/computer/v1.json", import.meta.url), "utf8"));

function exact(code: string, action: () => unknown): void {
  assert.throws(action, (error: unknown) => error instanceof DescriptionError && error.code === code);
}

function replacePath(value: any, path: (string | number)[], replacement: unknown): void {
  for (const part of path.slice(0, -1)) value = value[part];
  value[path.at(-1)!] = replacement;
}

for (const item of fixture.cases) {
  test(`shared Computer vector ${item.id}`, () => {
    const result = compileProgram(item.computer, item.requestId, item.expression);
    assert.deepEqual(result, item.expected);
    assert.equal(canonicalizeJson(result), item.canonical);
    assert.deepEqual(parseCompiledDescription(item.canonical), result);
    assert.deepEqual(validateCompiledProgram(item.computer, item.requestId, item.expression, result), result);
  });
}
for (const refusal of fixture.refusals) {
  test(`exact Computer refusal ${refusal.id}`, () => {
    const item = structuredClone(fixture.cases[0]);
    replacePath(item[refusal.section], refusal.path, refusal.value);
    exact(refusal.error, () => compileProgram(item.computer, item.requestId, item.expression));
  });
}
test("canonical parallel pipe syntax matches operator precedence vector", () => {
  const item = fixture.cases.find((item: any) => item.id === "operator_precedence");
  const [a, b, c, d, e] = item.expected.occurrences.map((occurrence: any) => ProgramExpr.leaf(occurrence.leaf));
  assert.deepEqual(compileProgram(item.computer, item.requestId, parallel(a, b, c).pipe(d).pipe(e)), item.expected);
});
test("occurrence identity retains retries and separates repeated leaves", () => {
  for (const name of ["repeated_parallel", "repeated_sequence"]) {
    const item = fixture.cases.find((item: any) => item.id === name);
    const result = compileProgram(item.computer, item.requestId, item.expression);
    assert.equal(new Set(result.occurrences.map(item => item.occurrenceId)).size, 2);
    assert.deepEqual(compileProgram(item.computer, item.requestId, item.expression), result);
    const other = compileProgram(item.computer, "different-request", item.expression);
    assert.ok(other.occurrences.every(item => !result.occurrences.some(original => original.occurrenceId === item.occurrenceId)));
  }
});
test("forged compiled descriptions refuse exact mutations", () => {
  const item = fixture.cases[0];
  const mutations: [(string | number)[], unknown][] = [
    [["digest"], "0".repeat(64)], [["requestId"], "other"], [["revisionId"], "0".repeat(64)],
    [["ownerDomain"], "other"], [["lifecycleGeneration"], 2],
    [["occurrences", 0, "occurrenceId"], "0".repeat(64)], [["occurrences", 0, "path"], [1]],
    [["occurrences", 0, "parents"], ["0".repeat(64)]],
    [["occurrences", 0, "leaf", "resources", 0, "generation"], 2],
  ];
  for (const [path, replacement] of mutations) {
    const supplied = structuredClone(item.expected); replacePath(supplied, path, replacement);
    exact("compiled_mismatch", () => validateCompiledProgram(item.computer, item.requestId, item.expression, supplied));
  }
  const supplied = structuredClone(item.expected); supplied.lifecycleGeneration = true;
  exact("generation", () => validateCompiledProgram(item.computer, item.requestId, item.expression, supplied));
  supplied.lifecycleGeneration = 1;
  supplied.occurrences[0].leaf.resources = Array(257).fill(supplied.occurrences[0].leaf.resources[0]);
  exact("resource_count", () => validateCompiledProgram(item.computer, item.requestId, item.expression, supplied));
});
test("decoder rejects exact byte depth string and collection overflow and duplicate keys", () => {
  assert.equal(parseDescription("0" + " ".repeat(2 * 1024 * 1024 - 1)), 0);
  exact("wire_bytes", () => parseDescription("0" + " ".repeat(2 * 1024 * 1024)));
  exact("json_shape", () => parseDescription('{"value":{"id":1,"id":2}}'));
  const maximum = "[".repeat(96) + "0" + "]".repeat(96);
  assert.deepEqual(parseDescription(maximum), JSON.parse(maximum));
  exact("json_depth", () => parseDescription("[".repeat(97) + "0" + "]".repeat(97)));
  assert.equal((parseDescription(JSON.stringify(Array(65536).fill(0))) as unknown[]).length, 65536);
  exact("json_entries", () => parseDescription(JSON.stringify(Array(65537).fill(0))));
  assert.equal(parseDescription(JSON.stringify("é".repeat(512))), "é".repeat(512));
  exact("string_bytes", () => parseDescription(JSON.stringify("é".repeat(512) + "a")));
});
test("expression depth and parent count accept maximum and reject one over", () => {
  const item = fixture.cases[0]; let expression = item.expression;
  for (let index = 0; index < 31; index++) expression = { op: "sequence", items: [item.expression, expression] };
  assert.equal(compileProgram(item.computer, item.requestId, expression).occurrences.length, 32);
  expression = { op: "sequence", items: [item.expression, expression] };
  exact("expression_depth", () => compileProgram(item.computer, item.requestId, expression));
  assert.equal(compileProgram(item.computer, item.requestId, { op: "parallel", items: Array(16).fill(item.expression) }).occurrences.length, 16);
  exact("parent_count", () => compileProgram(item.computer, item.requestId, { op: "parallel", items: Array(17).fill(item.expression) }));
});

test("compiled collection maximum and one over have bounded outcomes", () => {
  assert.equal((parseCompiledDescription(JSON.stringify(Array(262144).fill(0))) as unknown[]).length, 262144);
  exact("json_entries", () => parseCompiledDescription(JSON.stringify(Array(262145).fill(0))));
});

test("original numbers retain exact integral identity", () => {
  for (const item of [...fixture.numbers, ...fixture.wireStrings]) {
    if (item.error) exact(item.error, () => parseDescription(item.source));
    else assert.deepEqual(parseDescription(item.source), item.value);
  }
  const item = fixture.cases[0], text = JSON.stringify(item.computer);
  for (const number of ["1.0", "1e0", "10e-1"]) assert.deepEqual(compileProgram(parseDescription(text.replace('"lifecycleGeneration":1', '"lifecycleGeneration":' + number)), item.requestId, item.expression), item.expected);
  assert.equal(parseDescription('"1.00000000000000001"'), "1.00000000000000001");
  assert.deepEqual(parseDescription(String.raw`{"text":"quote\"1.00000000000000001","value":1.0}`), { text: 'quote"1.00000000000000001', value: 1 });
  exact("json_shape", () => parseDescription('{"value":{"id":1.0,"id":1e0}}'));
});
test("nullable parent is required and nested fields are closed", () => {
  const item = structuredClone(fixture.cases[0]);
  compileProgram(item.computer, item.requestId, item.expression);
  delete item.computer.record.parentRevision;
  exact("json_shape", () => compileProgram(item.computer, item.requestId, item.expression));
  const nested = structuredClone(fixture.cases[0]); nested.computer.revision.boot.extra = true;
  exact("json_shape", () => compileProgram(nested.computer, nested.requestId, nested.expression));
});

test("Unicode scalar values are required for strings and keys", () => {
  assert.equal(parseDescription(String.raw`"\ud83d\ude00"`), "😀");
  for (const text of [String.raw`"\ud800"`, String.raw`{"\ud800":0}`, '"' + String.fromCharCode(0xd800) + '"']) exact("json_shape", () => parseDescription(text));
});

function pin(computer: any): void {
  computer.revision.namespaceDigest = namespaceDigest(computer.revision.resources);
  computer.revision.revisionId = revisionDigest(computer.revision);
  computer.record.headRevision = computer.revision.revisionId;
  computer.image.revisionId = computer.revision.revisionId;
  computer.image.resourceManifestDigest = computer.revision.namespaceDigest;
}
test("expression node leaf and edge limits accept maxima and reject one over", () => {
  const item = fixture.cases[0]; let expression = item.expression;
  for (let index = 0; index < 10; index++) expression = { op: "sequence", items: [expression, expression] };
  const result = compileProgram(item.computer, item.requestId, expression);
  assert.equal(result.occurrences.length, 1024);
  assert.deepEqual(parseCompiledDescription(canonicalizeJson(result)), result);
  for (const [count, error] of [[2047, "expression_nodes"], [1025, "leaf_count"]] as const) exact(error, () => compileProgram(item.computer, item.requestId, { op: "sequence", items: Array(count).fill(item.expression) }));
  function stage(parents: number, width: number): any {
    const leaf = structuredClone(item.expression); const schema = leaf.leaf.outputSchema;
    leaf.leaf.inputSchema = parents === 1 ? { kind: "value", schema } : { kind: "all_success", schemas: Array(parents).fill(schema) };
    return width === 1 ? leaf : { op: "parallel", items: Array(width).fill(leaf) };
  }
  const stages = [stage(1, 16), ...Array.from({ length: 15 }, () => stage(16, 16)), stage(16, 15), stage(15, 1), stage(1, 1)];
  const maximum = compileProgram(item.computer, item.requestId, { op: "sequence", items: stages });
  assert.equal(maximum.occurrences.reduce((total, item) => total + item.parents.length, 0), 4096);
  stages.push(stage(1, 1));
  exact("dependency_edges", () => compileProgram(item.computer, item.requestId, { op: "sequence", items: stages }));
});
test("resource and profile maxima are accepted and one over refuses", () => {
  let item = structuredClone(fixture.cases[0]);
  const original = item.computer.revision.resources[0];
  for (let index = 0; index < 255; index++) item.computer.revision.resources.push({ ...structuredClone(original), namespace: `/resource-${index}` });
  pin(item.computer); compileProgram(item.computer, item.requestId, item.expression);
  item.computer.revision.resources.push(original);
  exact("resource_count", () => compileProgram(item.computer, item.requestId, item.expression));
  item = structuredClone(fixture.cases[0]); const profiles = item.computer.revision.profileRefs;
  for (let index = 0; index < 63; index++) profiles.push({ ...structuredClone(profiles[0]), artifactId: `profile-${index}` });
  item.computer.record.profileRefs = profiles; item.computer.image.requirements = profiles;
  pin(item.computer); compileProgram(item.computer, item.requestId, item.expression);
  profiles.push(profiles[0]);
  exact("profiles", () => compileProgram(item.computer, item.requestId, item.expression));
});
test("identifier namespace generation and content byte maxima refuse one over", () => {
  let item = structuredClone(fixture.cases[0]);
  compileProgram(item.computer, "a".repeat(128), item.expression);
  for (const request of ["a".repeat(129), "a\n"]) exact("identifier", () => compileProgram(item.computer, request, item.expression));
  item.computer.record.lifecycleGeneration = Number.MAX_SAFE_INTEGER;
  compileProgram(item.computer, item.requestId, item.expression);
  item.computer.record.lifecycleGeneration++;
  exact("generation", () => compileProgram(item.computer, item.requestId, item.expression));
  item = structuredClone(fixture.cases[0]);
  const namespace = "/" + "a".repeat(128) + "/" + "b".repeat(126);
  item.computer.revision.resources[0].namespace = namespace; item.expression.leaf.resources[0].namespace = namespace;
  pin(item.computer); compileProgram(item.computer, item.requestId, item.expression);
  item.expression.leaf.resources[0].namespace += "b";
  exact("namespace", () => compileProgram(item.computer, item.requestId, item.expression));
  item = structuredClone(fixture.cases[0]); const pending = [item.computer, item.expression];
  while (pending.length) {
    const value = pending.pop();
    if (value !== null && typeof value === "object") {
      if ("byteLength" in value) value.byteLength = 0;
      for (const nested of Object.values(value)) pending.push(nested);
    }
  }
  item.expression.leaf.contract.byteLength = 64 * 1024 * 1024;
  pin(item.computer); compileProgram(item.computer, item.requestId, item.expression);
  item.expression.leaf.contract.byteLength++;
  exact("transfer_bytes", () => compileProgram(item.computer, item.requestId, item.expression));
});

test("revision digest bounds the excluded placeholder", () => {
  const revision = structuredClone(fixture.cases[0].computer.revision), expected = revisionDigest(revision);
  revision.revisionId = ""; assert.equal(revisionDigest(revision), expected);
  for (const value of ["0".repeat(65), "0".repeat(8 * 1024 * 1024)]) {
    revision.revisionId = value; exact("digest_format", () => revisionDigest(revision));
  }
});
