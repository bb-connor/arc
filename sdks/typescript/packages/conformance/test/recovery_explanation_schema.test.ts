import { readFileSync,readdirSync } from "node:fs";
import { dirname,resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe,expect,it } from "vitest";
import { createWireSchemaValidator } from "../../node-http/src/wire-schema.js";
import { RecoveryClient } from "../../node-http/src/recovery.js";
const root=resolve(dirname(fileURLToPath(import.meta.url)),"../../../../..");
const schemaRoot=resolve(root,"spec/schemas/chio-wire/v1");
const schemas=readdirSync(schemaRoot,{withFileTypes:true}).filter(e=>e.isDirectory()).flatMap(group=>readdirSync(resolve(schemaRoot,group.name)).filter(n=>n.endsWith(".schema.json")).flatMap(name=> {
 const schema=JSON.parse(readFileSync(resolve(schemaRoot,group.name,name),"utf8")) as {$id?:string};
 if(schema.$id===undefined) return [];
 const aliases=["chio.computer","chio.world"]
  .map(domain=>`https://${domain}/schemas/chio-wire/v1/${group.name}/${name}`)
  .filter(id=>id!==schema.$id);
 return [schema,...aliases.map(id=>({...schema,$id:id}))];
}));
const validate=createWireSchemaValidator(schemas);
const files:Record<string,string>={snapshot:"explanation-snapshot",registry:"remedy-registry",evaluation:"explanation-evaluation",report:"explanation-report",view:"explanation-view",signed_report:"signed-explanation-report",signed_view:"signed-explanation-view"};
const corpus=JSON.parse(readFileSync(resolve(root,"spec/vectors/recovery/v1/explanation-contracts.json"),"utf8")) as {vectors:{name:string,contract:string,wire:string,schema_valid:boolean}[]};
const positive=JSON.parse(readFileSync(resolve(root,"spec/vectors/recovery/v1/explanation-positive.json"),"utf8")) as {view:unknown,report:unknown};
describe("explanation advisory schema and transport",()=> {
 for(const vector of corpus.vectors) it(vector.name,()=>expect(validate(`https://chio.computer/schemas/chio-wire/v1/recovery/${files[vector.contract]}.schema.json`,JSON.parse(vector.wire))).toBe(vector.schema_valid));
 it("retrieves the separately signed view in one request",async()=> {
  let calls=0;
  const client=new RecoveryClient("https://host.example",async(url,options)=> {calls++;expect(String(url)).toBe("https://host.example/v1/recovery/explain");expect(options?.redirect).toBe("error");return new Response(JSON.stringify(positive.view));});
  const view=await client.explain("protected-capability","workflow");
  expect(view.body.projection).toBeDefined();expect(calls).toBe(1);expect(view.body).not.toHaveProperty("snapshot_digest");
 });
 it("refuses full reports and leaking extra fields without retry",async()=> {
  for(const reply of [positive.report,{...(positive.view as object),private_basis:"private-canary"}]) {
   let calls=0;const client=new RecoveryClient("https://host.example",async()=> {calls++;return new Response(JSON.stringify(reply));});
   await expect(client.explain("protected-capability","workflow")).rejects.toThrow("recovery.invalid_response");expect(calls).toBe(1);
  }
 });
});
