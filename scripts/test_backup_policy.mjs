import { build } from 'esbuild';
import { test } from 'node:test';
import assert from 'node:assert/strict';
const result = await build({entryPoints:['backupPolicy.ts'], bundle:true, write:false, format:'esm', platform:'node'});
const policy = await import('data:text/javascript;base64,' + Buffer.from(result.outputFiles[0].text).toString('base64'));
test('retains at most ten including the newly written backup and historical generations', () => {
  const now = 2_000_000_000;
  const revisions = Array.from({length: 150}, (_, i) => ({id:`old_${i}`, created_at:now - i * 86400}));
  revisions.push({id:'new', created_at:now});
  const keep = policy.selectBackupsToKeep(revisions, 'new');
  assert.equal(policy.MAX_CLOUD_BACKUPS, 10);
  assert.equal(keep.size, 10);
  assert(keep.has('new'));
  assert(keep.has('old_30'));
});
test('keeps all revisions below the limit and handles empty input', () => {
  const revisions = [{id:'a',created_at:100},{id:'b',created_at:100}];
  assert.deepEqual(policy.selectBackupsToKeep(revisions, 'b'), new Set(['b','a']));
  assert.equal(policy.selectBackupsToKeep([]).size, 0);
});
