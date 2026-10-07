import { expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { RecoveryClient } from "../../node-http/src/recovery.js";
import { canonicalJsonString } from "../../node-http/src/canonical.js";
import type { Recovery_DecisionReport, Recovery_PolicyMaintenanceProposal } from "../../node-http/src/_generated/index.js";
const cases = JSON.parse(readFileSync(new URL("../../../../../spec/vectors/recovery/v1/product-contracts.json", import.meta.url), "utf8")).cases;
const report: Recovery_DecisionReport.DecisionReportV1 = cases.find((v: {schema:string;valid:boolean}) => v.schema === "decision-report.schema.json" && v.valid).body;
const proposal: Recovery_PolicyMaintenanceProposal.PolicyMaintenanceProposalV1 = cases.find((v: {schema:string;valid:boolean}) => v.schema === "policy-maintenance-proposal.schema.json" && v.valid).body;
const label = { kind: "top" };
const influence = { commitment: Array(32).fill(8), externally_influenced: true, unknown: true };
it("carries stable report identity and typed classified proposal without retry", async () => {
  const requests: Record<string,string>[] = [];
  const client = new RecoveryClient("https://host.example", async (url, options) => {
    expect(options?.redirect).toBe("error");
    const body = JSON.parse(new TextDecoder().decode(options?.body as Uint8Array));
    requests.push(body);
    const reply = String(url).endsWith("policy/propose") ? {domain_version:1,digest:Array(32).fill(9),proposal,label,influence} :
      {domain_version:1,id:"retained-report",digest:Array(32).fill(7),report,label,influence};
    return new Response(JSON.stringify(reply));
  });
  const stored = await client.submitReport("capability", "stable-command", report);
  expect(stored.id).toBe("retained-report");
  expect((await client.readReport("capability", stored.id)).report).toEqual(report);
  expect((await client.proposePolicy("capability", proposal)).proposal).toEqual(proposal);
  expect(requests).toHaveLength(3);
  expect(requests[0].report).toBe(canonicalJsonString(report));
  expect(requests[0].command_id).toBe("stable-command");
});
it("refuses raw errors and undeclared response fields without retry", async () => {
  for (const reply of [new Response("private-error-canary", {status:503}),new Response(JSON.stringify({domain_version:1,id:"retained-report",digest:Array(32).fill(7),report,label,influence,grant:true}))]) {
    let calls = 0;
    const client = new RecoveryClient("https://host.example", async () => {calls++;return reply;});
    await expect(client.submitReport("private-capability-canary", "stable-command", report)).rejects.toThrow(/^recovery\./);
    expect(calls).toBe(1);
  }
});
