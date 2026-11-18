import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { deploymentConfiguration, deploy } from '../deploy.mjs';

const source = 'b'.repeat(40), digest = 'c'.repeat(64);
const config = JSON.parse(readFileSync(new URL('../wrangler.jsonc', import.meta.url), 'utf8'));
const seed = { schemaVersion: 1, recipeDigest: digest, compilerIdentityDigest: digest,
  target: 'x86_64-unknown-linux-gnu', cwd: '/tmp/omg-r2-read-probe-v1', sourceDigest: digest,
  argumentsDigest: digest, outputDigest: digest, outputBytes: 32, producerSourceSha: source,
  producerRunId: '123', producerAttempt: 1 };
const env = { GITHUB_ACTIONS: 'true', GITHUB_REPOSITORY: 'omg-cli/omg', GITHUB_REF: 'refs/heads/main',
  GITHUB_EVENT_NAME: 'workflow_dispatch', GITHUB_JOB: 'deploy', GITHUB_SHA: source,
  GITHUB_WORKFLOW_REF: 'omg-cli/omg/.github/workflows/cloudflare-artifacts.yml@refs/heads/main',
  GITHUB_RUN_ID: '123', GITHUB_RUN_ATTEMPT: '1', CLOUDFLARE_ACCOUNT_ID: 'a'.repeat(32),
  OMG_R2_CACHE_ACCOUNT_ID: 'a'.repeat(32), CLOUDFLARE_API_TOKEN: 'synthetic-api-token',
  OMG_R2_CACHE_ACCESS_KEY_ID: 'synthetic-parent-id', OMG_R2_CACHE_SECRET_ACCESS_KEY: 'synthetic-parent-secret' };

test('bootstrap refuses untrusted identity, stale seed and native/additional bindings', () => {
  assert.equal(deploymentConfiguration(config, env, seed).name, 'omg-ci-artifacts');
  for (const change of [{ GITHUB_REF: 'refs/pull/1/merge' }, { GITHUB_EVENT_NAME: 'pull_request' },
    { GITHUB_JOB: 'native' }, { CLOUDFLARE_ACCOUNT_ID: 'd'.repeat(32) }]) {
    assert.throws(() => deploymentConfiguration(config, { ...env, ...change }, seed));
  }
  for (const change of [{ name: 'omg-native-ci' }, { containers: [] }, { ai: {} },
    { r2_buckets: [{ binding: 'DEPENDENCIES', bucket_name: 'other' }] }]) {
    assert.throws(() => deploymentConfiguration({ ...config, ...change }, env, seed));
  }
  assert.throws(() => deploymentConfiguration(config, env, { ...seed, producerSourceSha: 'd'.repeat(40) }));
});

test('deployment streams only existing parent pair over stdin and reads final version after bulk', async () => {
  const directory = mkdtempSync(path.join(tmpdir(), 'omg-artifact-deploy-test-'));
  const receiptPath = path.join(directory, 'seed.json'); writeFileSync(receiptPath, JSON.stringify(seed));
  const calls = []; let bulk = false;
  try {
    const result = await deploy({ env: { ...env, RUNNER_TEMP: directory, OMG_R2_CACHE_SEED_RECEIPT: receiptPath },
      run(command, args, options) {
        calls.push({ command, args, input: options.input });
        assert(!args.some(arg => arg.includes('synthetic-')));
        if (args.includes('bulk')) {
          bulk = true;
          assert.deepEqual(JSON.parse(options.input), { R2_PARENT_ACCESS_KEY_ID: env.OMG_R2_CACHE_ACCESS_KEY_ID,
            R2_PARENT_SECRET_ACCESS_KEY: env.OMG_R2_CACHE_SECRET_ACCESS_KEY });
        } else assert.equal(options.input, undefined);
        return { status: 0, stdout: command === 'git' && args[0] === 'rev-parse' ? source :
          'https://omg-ci-artifacts.example.workers.dev\n' };
      },
      async fetcher(url, options) {
        assert(bulk, 'readback must follow secret bulk final deployment');
        if (url.includes('api.cloudflare.com')) return Response.json({ success: true, result: { deployments: [{
          id: '11111111-1111-1111-1111-111111111111', created_on: new Date().toISOString(),
          versions: [{ percentage: 100, version_id: '22222222-2222-2222-2222-222222222222' }],
        }] } });
        assert.equal(new Headers(options.headers).has('authorization'), false);
        if (url.endsWith('/health')) return Response.json({ sourceSha: source, policyVersion: 'portable-read-v1', seedRecipeDigest: digest });
        return new Response(null, { status: 401 });
      } });
    assert.equal(result.versionId, '22222222-2222-2222-2222-222222222222');
    assert.deepEqual(result.seedMarkers, {
      allowedKey: `portable-v1/admission-v1/${digest}/123-1.json`,
      deniedKey: `benchmark-v1/admission-v1/${digest}/123-1.json`,
      sha256: '18bc06888e835b80ec49441942a59237ff920caa764645e29534a70f671e7dc7',
    });
    assert(calls.some(call => call.args.includes('--dry-run')));
    const proof = readFileSync(path.join(directory, 'omg-ci-artifacts-deployment.json'), 'utf8');
    assert(!proof.includes('synthetic-'));
  } finally { rmSync(directory, { recursive: true, force: true }); }
});
