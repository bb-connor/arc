import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { RecoveryClient } from "../src/recovery.js";
import { RecoveryError } from "../src/recovery-errors.js";
import type { RecoveryCommandResponseV1 } from "../src/_generated/index.js";

type StateCases = {
  effects: RecoveryCommandResponseV1["effect"][];
  controls: RecoveryCommandResponseV1["control"][];
  releases: RecoveryCommandResponseV1["release"][];
  errors: { status: number; code: string }[];
};
const cases = JSON.parse(readFileSync(new URL(
  "../../../../tests/recovery-response-states.json", import.meta.url), "utf8")) as StateCases;
const command = { schema: "chio.recovery.command.v1", version: 1, command_id: "command",
  command: { kind: "inspect_workflow", workflow_id: "workflow" } } as const;

describe("native recovery states remain distinct at every response route", () => {
  // This product checks the wire contract, not native state reachability.
  for (const effect of cases.effects) for (const control of cases.controls) for (const release of cases.releases) {
    it(`${effect.kind}/${control}/${release.kind}`, async () => {
      const native = { command_id: "command", workflow_id: "workflow", revision: 1,
        effect, control, release };
      const paths: string[] = [];
      const client = new RecoveryClient("http://localhost:1", async (url) => {
        const path = new URL(String(url)).pathname;
        paths.push(path);
        return new Response(JSON.stringify(path.endsWith("/settle") ? native : { status: native }),
          { headers: { "content-type": "application/json" } });
      });
      expect((await client.execute("synthetic-capability", command)).status).toEqual(native);
      expect(await client.settle("synthetic-capability", "workflow")).toEqual(native);
      expect(paths).toEqual(["/v1/recovery/commands", "/v1/recovery/settle"]);
    });
  }

  it.each(cases.errors)("retains $code without changing its error type", async ({ status, code }) => {
    let calls = 0;
    const client = new RecoveryClient("http://localhost:1", async () => {
      calls++;
      return new Response(code, { status });
    });
    let error: unknown;
    try { await client.execute("synthetic-capability", command); } catch (caught) { error = caught; }
    expect(error).toBeInstanceOf(RecoveryError);
    expect(error).toMatchObject({ code, message: code });
    expect(calls).toBe(1);
  });
});

