import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import net from 'node:net';
import { pathToFileURL } from 'node:url';

const root = process.env.PAPERCLIP_LOCAL_ROOT;
const scratch = process.env.PAPERCLIP_RUN_SCRATCH_DIR;
assert.ok(root && scratch, 'Set PAPERCLIP_LOCAL_ROOT and use the injected run scratch directory');
const moduleAt = (relative) => import(pathToFileURL(path.join(root, relative)).href);
const { default: EmbeddedPostgres } = await moduleAt('node_modules/embedded-postgres/dist/index.js');
const { drizzle } = await moduleAt('node_modules/drizzle-orm/node-postgres/index.js');
const servicePath = path.join(root, 'node_modules/@paperclipai/server/dist/services/cross-issue-influence-limit.js');
let serviceUrl = pathToFileURL(servicePath).href;
if (process.env.PER_471_CANDIDATE === '1') {
  const { patchCrossIssueAttribution } = await import('./cross-issue-attribution.mjs');
  let source = patchCrossIssueAttribution(await fs.readFile(servicePath, 'utf8'));
  // Resolve the candidate's original imports without installing or copying dependencies.
  for (const [specifier, relative] of Object.entries({
    'drizzle-orm': 'node_modules/drizzle-orm/index.js',
    '@paperclipai/db': 'node_modules/@paperclipai/db/dist/index.js',
    '@paperclipai/shared': 'node_modules/@paperclipai/shared/dist/index.js',
    '../errors.js': 'node_modules/@paperclipai/server/dist/errors.js',
    '../middleware/logger.js': 'node_modules/@paperclipai/server/dist/middleware/logger.js',
  })) source = source.replaceAll(JSON.stringify(specifier), JSON.stringify(pathToFileURL(path.join(root, relative)).href));
  const candidate = path.join(scratch, 'per-471-candidate.mjs');
  await fs.writeFile(candidate, source);
  serviceUrl = pathToFileURL(candidate).href;
}
const { observeCrossIssueInfluence } = await import(serviceUrl);
const port = await new Promise((resolve, reject) => {
  const server = net.createServer();
  server.on('error', reject);
  server.listen(0, '127.0.0.1', () => {
    const address = server.address();
    assert.ok(address && typeof address === 'object');
    server.close(() => resolve(address.port));
  });
});
const postgres = new EmbeddedPostgres({
  databaseDir: path.join(scratch, `per-471-postgres-${process.pid}`),
  port, authMethod: 'trust', persistent: true,
  postgresFlags: ['-h', '127.0.0.1'], onLog() {}, onError(message) { process.stderr.write(message); },
});
const company = '00000000-0000-4000-8000-000000000001';
const agent = '00000000-0000-4000-8000-000000000002';
const run = '00000000-0000-4000-8000-000000000003';
const sourceIssue = '00000000-0000-4000-8000-000000000004';
const targetIssue = '00000000-0000-4000-8000-000000000005';
const other = '00000000-0000-4000-8000-000000000006';
const input = { companyId: company, agentId: agent, runId: run, targetIssueId: targetIssue,
  kind: 'update', now: new Date('2026-10-04T00:00:00Z') };

test('persisted cross-issue attribution and cap on isolated PostgreSQL', async (t) => {
  await postgres.initialise();
  await postgres.start();
  const client = postgres.getPgClient('postgres', '127.0.0.1');
  try {
    await client.connect();
    await client.query(`CREATE TABLE heartbeat_runs (
      id uuid PRIMARY KEY, company_id uuid, agent_id uuid, responsible_user_id text, context_snapshot jsonb);
      CREATE TABLE activity_log (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), company_id uuid,
      actor_type text, actor_id text, agent_id uuid, run_id uuid, responsible_user_id text,
      action text, entity_type text, entity_id text, details jsonb, created_at timestamptz DEFAULT now());`);
    const db = drizzle(client);
    async function fixture(context = {}, checkout = true, checkoutCompany = company, checkoutAgent = agent) {
      await client.query('TRUNCATE heartbeat_runs, activity_log');
      await client.query('INSERT INTO heartbeat_runs VALUES ($1,$2,$3,NULL,$4)', [run, company, agent, context]);
      if (checkout) await client.query(`INSERT INTO activity_log
        (company_id, actor_type, actor_id, agent_id, run_id, action, entity_type, entity_id)
        VALUES ($1,'agent',$2::text,$2::uuid,$3,'issue.checked_out','issue',$4)`,
      [checkoutCompany, checkoutAgent, run, sourceIssue]);
    }
    const denial = (error) => error.status === 403 && error.details?.code === 'cross_issue_influence_run_context_required';
    await t.test('timer run uses its first authenticated checkout as source', async () => {
      await fixture({ wakeReason: 'heartbeat_timer', source: 'scheduler' });
      const result = await observeCrossIssueInfluence(db, input);
      assert.equal(result.allowed, true);
      const { rows } = await client.query("SELECT details FROM activity_log WHERE action='issue.cross_issue_influence_observed'");
      assert.equal(rows[0].details.sourceIssueId, sourceIssue);
    });
    await t.test('task snapshot remains authoritative over checkout fallback', async () => {
      await fixture({ issueId: other });
      await observeCrossIssueInfluence(db, input);
      const { rows } = await client.query("SELECT details FROM activity_log WHERE action='issue.cross_issue_influence_observed'");
      assert.equal(rows[0].details.sourceIssueId, other);
    });
    await t.test('same source issue does not consume a cross-issue attempt', async () => {
      await fixture();
      assert.equal(await observeCrossIssueInfluence(db, { ...input, targetIssueId: sourceIssue }), null);
    });
    await t.test('unscoped run without checkout remains denied', async () => {
      await fixture({}, false);
      await assert.rejects(observeCrossIssueInfluence(db, input), denial);
    });
    await t.test('checkout from another company or agent cannot provide source', async () => {
      await fixture({}, true, other);
      await assert.rejects(observeCrossIssueInfluence(db, input), denial);
      await fixture({}, true, company, other);
      await assert.rejects(observeCrossIssueInfluence(db, input), denial);
    });
    await t.test('foreign and malformed run identities remain denied', async () => {
      await fixture({ issueId: sourceIssue });
      await assert.rejects(observeCrossIssueInfluence(db, { ...input, agentId: other }), denial);
      await assert.rejects(observeCrossIssueInfluence(db, { ...input, companyId: other }), denial);
      await assert.rejects(observeCrossIssueInfluence(db, { ...input, runId: 'not-a-uuid' }), denial);
    });
    await t.test('only a server checkout attributed to this actor can supply source', async () => {
      for (const [column, value] of [['actor_type', 'board'], ['actor_id', other],
        ['action', 'issue.updated'], ['entity_type', 'agent'], ['entity_id', 'malformed']]) {
        await fixture();
        // Column names are a fixed test-owned list; values are bound parameters.
        await client.query(`UPDATE activity_log SET ${column}=$1`, [value]);
        await assert.rejects(observeCrossIssueInfluence(db, input), denial);
      }
    });
    await t.test('later checkout cannot rebase the source or reset the counter', async () => {
      await fixture();
      await client.query(`INSERT INTO activity_log
        (company_id, actor_type, actor_id, agent_id, run_id, action, entity_type, entity_id, created_at)
        VALUES ($1,'agent',$2::text,$2::uuid,$3,'issue.checked_out','issue',$4,now()+interval '1 second')`, [company, agent, run, other]);
      const first = await observeCrossIssueInfluence(db, input);
      const second = await observeCrossIssueInfluence(db, input);
      assert.equal(first.count, 1);
      assert.equal(second.count, 2);
      const { rows } = await client.query("SELECT details FROM activity_log WHERE action='issue.cross_issue_influence_observed'");
      assert.ok(rows.every(row => row.details.sourceIssueId === sourceIssue));
    });
    await t.test('concurrent attempts serialize at the unchanged cap', async () => {
      await fixture();
      const { default: pg } = await moduleAt('node_modules/pg/lib/index.js');
      const pool = new pg.Pool({ host: '127.0.0.1', port, user: 'postgres', database: 'postgres', max: 4 });
      try {
        const results = await Promise.all(Array.from({ length: 22 }, () => observeCrossIssueInfluence(drizzle(pool), input)));
        assert.equal(results.filter(result => result.allowed).length, 20);
        assert.equal(results.filter(result => !result.allowed).length, 2);
        assert.equal(Math.max(...results.map(result => result.count)), 21);
      } finally { await pool.end(); }
    });
  } finally {
    await client.end();
    await postgres.stop();
  }
});

if (process.env.PER_471_CANDIDATE === '1') {
  test('candidate refuses drift in installed service bytes', async () => {
    const { patchCrossIssueAttribution } = await import('./cross-issue-attribution.mjs');
    const source = await fs.readFile(servicePath, 'utf8');
    assert.throws(() => patchCrossIssueAttribution(`${source}\n`), /Unsupported.*SHA-256/);
    assert.throws(() => patchCrossIssueAttribution(patchCrossIssueAttribution(source)), /Unsupported.*SHA-256/);
  });
}
