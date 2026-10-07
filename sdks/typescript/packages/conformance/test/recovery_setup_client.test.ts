import { expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { RecoveryClient } from "../../node-http/src/recovery.js";
import { canonicalJsonString } from "../../node-http/src/canonical.js";
const cases = JSON.parse(readFileSync(new URL("../../../../../spec/vectors/recovery/v1/product-contracts.json", import.meta.url), "utf8")).cases;
const probe = cases.find((v: { name: string }) => v.name === "signed-recovery-setup-probe.schema.json").body;
const report = cases.find((v: { name: string }) => v.name === "signed-recovery-setup-report.schema.json").body;
it("preserves exact native setup proof and makes one request per explicit action", async () => {
  const requests: Record<string,string>[] = [];
  const client = new RecoveryClient("https://host.example", async (url, options) => {
    expect(options?.redirect).toBe("error");
    requests.push(JSON.parse(new TextDecoder().decode(options?.body as Uint8Array)));
    return new Response(JSON.stringify(String(url).endsWith("probe") ? probe : report));
  });
  expect(await client.setupProbe("cap", "self-test")).toEqual(probe);
  const exact = canonicalJsonString(probe);
  expect(await client.setupQualify("cap", exact)).toEqual(report);
  expect(requests).toEqual([{capability:"cap",workflow_id:"self-test"},{capability:"cap",probe:exact}]);
});
it("rejects invalid or oversized proof before contacting the host", () => {
  let calls = 0;
  const client = new RecoveryClient("https://host.example", async () => { calls++; return new Response("{}"); });
  for (const proof of ["{}", "x".repeat(32769)]) {
    expect(() => client.setupQualify("cap", proof)).toThrow(/^recovery\./);
  }
  expect(calls).toBe(0);
});
