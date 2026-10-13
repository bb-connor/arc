import { readFileSync, readdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { createWireSchemaValidator } from "../../node-http/src/wire-schema.js";
import { RecoveryClient } from "../../node-http/src/recovery.js";
import type { Recovery_ActionIntent, Recovery_Command } from "../../node-http/src/_generated/index.js";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../../../../..");
const schemaRoot = resolve(root,"spec/schemas/chio-wire/v1");
const schemas = readdirSync(schemaRoot,{withFileTypes:true}).filter(entry=>entry.isDirectory()).map(entry=>entry.name).flatMap(group => readdirSync(resolve(schemaRoot,group))
  .filter(name => name.endsWith(".schema.json"))
  .flatMap(name => {
    const schema = JSON.parse(readFileSync(resolve(schemaRoot,group,name),"utf8")) as {$id?:string};
    if (schema.$id === undefined) return [];
    const aliases = ["chio.computer", "chio.world"]
      .map(domain => `https://${domain}/schemas/chio-wire/v1/${group}/${name}`)
      .filter(id => id !== schema.$id);
    return [schema, ...aliases.map(id => ({ ...schema, $id: id }))];
  }));
const validate = createWireSchemaValidator(schemas);
const files: Record<string,string> = {action:"action-intent",requirements:"authorization-requirements",grant_binding:"grant-binding",approval_intent:"approval-intent",grant:"signed-grant-v2",coverage:"signed-authority-coverage",provider_finality:"signed-provider-finality",provider_body:"provider-finality"};
const corpus = JSON.parse(readFileSync(resolve(root,"spec/vectors/recovery/v1/authority-contracts.json"),"utf8")) as {vectors:{name:string,contract:string,wire:string,schema_valid:boolean}[]};
const positive = JSON.parse(readFileSync(resolve(root,"spec/vectors/recovery/v1/authority-positive.json"),"utf8")) as {
  action: Recovery_ActionIntent.RecoveryExactActionIntentV1;
  command: Recovery_Command.RecoveryCommandV1;
  command_result: unknown;
  review_document: { canonical_preview: string };
};
describe("shared native recovery native vectors", () => {
  for (const vector of corpus.vectors) it(vector.name, () => {
    const name = files[vector.contract] ?? vector.contract.replaceAll("_","-");
    expect(validate(`https://chio.world/schemas/chio-wire/v1/recovery/${name}.schema.json`,JSON.parse(vector.wire))).toBe(vector.schema_valid);
  });
  it("public SDK returns a typed actual native receipt projection", async () => {
    const client = new RecoveryClient("https://host.example",async () => new Response(JSON.stringify(positive.command_result)));
    const result = await client.execute("synthetic-control-capability",positive.command);
    expect(result.status.effect.kind).toBe("complete");
    expect(result.original_response?.receipt).toBeDefined();
  });
  it("current native review preserves the original operation claim", () => {
    const origin = positive.action.origin;
    expect(origin, "current native actions must identify the original denial").toBeDefined();
    expect(validate("https://chio.world/schemas/chio-wire/v1/recovery/action-intent.schema.json", positive.action)).toBe(true);
    const preview = JSON.parse(positive.review_document.canonical_preview) as [Recovery_ActionIntent.RecoveryExactActionIntentV1];
    expect(preview[0].origin).toEqual(origin);
  });
  it("an explicitly null original claim is outside the closed action wire shape", () => {
    expect(validate("https://chio.world/schemas/chio-wire/v1/recovery/action-intent.schema.json", { ...positive.action, origin: null })).toBe(false);
  });
});
