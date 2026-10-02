// Python owns durable SQLite writes; no shell or private signing key is involved.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
const script=fileURLToPath(new URL('../../examples/funded-work/rail_journal.py',import.meta.url));
export function journal(config,command,fields={}) {
  const request={command,path:config.path,owner:config.owner,domain:config.domain,...fields};
  const result=spawnSync(config.python,['-B',script],{input:JSON.stringify(request),encoding:'utf8',timeout:15000,maxBuffer:512*1024});
  assert.equal(result.status,0,`journal ${command}: ${result.stderr || result.error}`);
  return JSON.parse(result.stdout);
}
