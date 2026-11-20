import { appendFileSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { isDeepStrictEqual } from 'node:util';

const here = fileURLToPath(new URL('.', import.meta.url));
const root = fileURLToPath(new URL('../../', import.meta.url));
const policy = 'portable-read-v1';
class DeploymentFailure extends Error {}
const require = (condition, message) => { if (!condition) throw new DeploymentFailure(message); };

export function deploymentConfiguration(config, env, seed) {
  require(env.GITHUB_ACTIONS === 'true' && env.GITHUB_REPOSITORY === 'omg-cli/omg' &&
    env.GITHUB_REF === 'refs/heads/main' && ['push', 'workflow_dispatch'].includes(env.GITHUB_EVENT_NAME) &&
    env.GITHUB_JOB === 'deploy' && env.GITHUB_WORKFLOW_REF ===
    'omg-cli/omg/.github/workflows/cloudflare-artifacts.yml@refs/heads/main', 'trusted-main deployment required');
  require(/^[a-f0-9]{40}$/.test(env.GITHUB_SHA ?? '') && /^[a-f0-9]{32}$/.test(env.CLOUDFLARE_ACCOUNT_ID ?? '') &&
    /^[1-9][0-9]{0,19}$/.test(env.GITHUB_RUN_ID ?? '') && /^[1-9][0-9]{0,5}$/.test(env.GITHUB_RUN_ATTEMPT ?? '') &&
    env.CLOUDFLARE_ACCOUNT_ID === env.OMG_R2_CACHE_ACCOUNT_ID, 'deployment identity mismatch');
  require(config.name === 'omg-ci-artifacts' && config.main === 'src/index.ts' &&
    config.workers_dev === true && config.preview_urls === false &&
    Object.keys(config).every(key => ['$schema', 'name', 'main', 'compatibility_date', 'workers_dev', 'preview_urls',
      'durable_objects', 'exports', 'r2_buckets', 'vars', 'limits', 'observability'].includes(key)) &&
    !['containers', 'workflows', 'ai', 'artifacts', 'services', 'kv_namespaces'].some(key => key in config) &&
    isDeepStrictEqual(config.r2_buckets, [{ binding: 'DEPENDENCIES', bucket_name: 'omg-ci-compiler-cache' }]) &&
    isDeepStrictEqual(config.durable_objects, { bindings: [{ name: 'CACHE_MINTS', class_name: 'CacheMintBudget' }] }) &&
    isDeepStrictEqual(config.exports, { CacheMintBudget: { type: 'durable-object', storage: 'sqlite' } }),
  'unexpected deployment target or bindings');
  const fields = ['schemaVersion', 'recipeDigest', 'compilerIdentityDigest', 'target', 'cwd', 'sourceDigest',
    'argumentsDigest', 'outputDigest', 'outputBytes', 'producerSourceSha', 'producerRunId', 'producerAttempt'];
  require(seed && isDeepStrictEqual(Object.keys(seed).sort(), fields.sort()) && seed.schemaVersion === 1 &&
    ['recipeDigest', 'compilerIdentityDigest', 'sourceDigest', 'argumentsDigest', 'outputDigest'].every(
      name => /^[a-f0-9]{64}$/.test(seed[name] ?? '')) && seed.target === 'x86_64-unknown-linux-gnu' &&
    seed.cwd === '/tmp/omg-r2-read-probe-v1' && Number.isSafeInteger(seed.outputBytes) &&
    seed.outputBytes > 0 && seed.outputBytes <= 1024 * 1024 && seed.producerSourceSha === env.GITHUB_SHA &&
    seed.producerRunId === env.GITHUB_RUN_ID && seed.producerAttempt === Number(env.GITHUB_RUN_ATTEMPT),
  'seed does not belong to this successful trusted producer');
  return { ...config, main: path.join(here, 'src/index.ts'), account_id: env.CLOUDFLARE_ACCOUNT_ID,
    vars: { R2_ACCOUNT_ID: env.CLOUDFLARE_ACCOUNT_ID, SOURCE_SHA: env.GITHUB_SHA, CACHE_SEED: JSON.stringify(seed) } };
}

export async function deploy({ env = process.env, run = spawnSync, fetcher = fetch } = {}) {
  const receiptPath = env.OMG_R2_CACHE_SEED_RECEIPT;
  require(receiptPath && statSync(receiptPath).isFile() && statSync(receiptPath).size <= 8192, 'bounded seed receipt required');
  const seed = JSON.parse(readFileSync(receiptPath, 'utf8'));
  const config = deploymentConfiguration(JSON.parse(readFileSync(path.join(here, 'wrangler.jsonc'), 'utf8')), env, seed);
  require(env.CLOUDFLARE_API_TOKEN && env.OMG_R2_CACHE_ACCESS_KEY_ID && env.OMG_R2_CACHE_SECRET_ACCESS_KEY,
    'existing deployment and R2 credentials required');
  const scratch = mkdtempSync(path.join(env.RUNNER_TEMP, 'omg-ci-artifacts-deploy-'));
  const call = (command, args, input) => {
    const operation = command === 'git' ? args[0] : args.includes('bulk') ? 'secret-bulk'
      : args.includes('--dry-run') ? 'dry-run' : 'deploy';
    const result = run(command, args, { cwd: root, env: { ...env, WRANGLER_SEND_METRICS: 'false', CI: 'true' },
      input, encoding: 'utf8', timeout: 180000, maxBuffer: 1024 * 1024 });
    require(!result.error && result.status === 0, `artifact deployment ${operation} failed (exit ${result.status})`);
    return result.stdout.trim();
  };
  try {
    require(call('git', ['rev-parse', 'HEAD']) === env.GITHUB_SHA, 'checkout differs from deployment source');
    call('git', ['diff', '--exit-code', 'HEAD', '--', 'services/ci-artifacts', 'scripts/ci-r2-cache.py']);
    const configPath = path.join(scratch, 'wrangler.json');
    writeFileSync(configPath, JSON.stringify(config));
    const wrangler = path.join(root, 'services/ci/node_modules/wrangler/bin/wrangler.js');
    const args = [wrangler, 'deploy', '--config', configPath];
    call(process.execPath, [...args, '--dry-run', '--outdir', path.join(scratch, 'bundle')]);
    const output = call(process.execPath, [...args, '--message', `source:${env.GITHUB_SHA}`]);
    const endpoints = [...new Set(output.match(/https:\/\/omg-ci-artifacts\.[a-z0-9-]+\.workers\.dev\b/g))];
    require(endpoints.length === 1, 'missing or ambiguous Worker endpoint');
    const endpoint = endpoints[0];
    call(process.execPath, [wrangler, 'secret', 'bulk', '--config', configPath], JSON.stringify({
      R2_PARENT_ACCESS_KEY_ID: env.OMG_R2_CACHE_ACCESS_KEY_ID,
      R2_PARENT_SECRET_ACCESS_KEY: env.OMG_R2_CACHE_SECRET_ACCESS_KEY,
    }));
    const response = await fetcher(`https://api.cloudflare.com/client/v4/accounts/${env.CLOUDFLARE_ACCOUNT_ID}/workers/scripts/omg-ci-artifacts/deployments`, {
      redirect: 'error', signal: AbortSignal.timeout(15000), headers: { Authorization: `Bearer ${env.CLOUDFLARE_API_TOKEN}` },
    });
    require(response.ok, `deployment readback failed (HTTP ${response.status})`);
    const raw = await response.text(); require(raw.length <= 65536, 'oversized deployment readback');
    const api = JSON.parse(raw);
    const deployments = api.result?.deployments;
    require(api.success === true && Array.isArray(deployments) && deployments.length > 0, 'invalid deployment readback');
    const latest = deployments.toSorted((a, b) => Date.parse(b.created_on) - Date.parse(a.created_on))[0];
    require(/^[a-f0-9-]{36}$/.test(latest.id ?? '') && latest.versions?.length === 1 &&
      latest.versions[0].percentage === 100 && /^[a-f0-9-]{36}$/.test(latest.versions[0].version_id ?? ''),
    'ambiguous final deployment version');
    const healthResponse = await fetcher(`${endpoint}/health`, { redirect: 'error', signal: AbortSignal.timeout(15000) });
    require(healthResponse.ok, 'Worker health failed');
    const health = await healthResponse.json();
    require(health.sourceSha === env.GITHUB_SHA && health.policyVersion === policy &&
      health.seedRecipeDigest === seed.recipeDigest, 'Worker source/policy/seed readback mismatch');
    const refusal = await fetcher(`${endpoint}/v1/compiler-cache/credentials`, {
      method: 'POST', redirect: 'error', signal: AbortSignal.timeout(15000),
    });
    require(refusal.status === 401, 'unauthenticated credential request was not refused');
    const receipt = { schemaVersion: 1, sourceSha: env.GITHUB_SHA, runId: env.GITHUB_RUN_ID,
      runAttempt: Number(env.GITHUB_RUN_ATTEMPT), endpoint, policyVersion: policy,
      seedRecipeDigest: seed.recipeDigest, seedOutputDigest: seed.outputDigest,
      seedMarkers: {
        allowedKey: `portable-v1/admission-v1/${seed.recipeDigest}/${seed.producerRunId}-${seed.producerAttempt}.json`,
        deniedKey: `benchmark-v1/admission-v1/${seed.recipeDigest}/${seed.producerRunId}-${seed.producerAttempt}.json`,
        sha256: createHash('sha256').update(JSON.stringify(Object.fromEntries(
          Object.keys(seed).sort().map(key => [key, seed[key]]))) + '\n').digest('hex'),
      },
      configurationSha256: createHash('sha256').update(JSON.stringify(config)).digest('hex'),
      deploymentId: latest.id, versionId: latest.versions[0].version_id, verifiedAt: new Date().toISOString() };
    writeFileSync(path.join(env.RUNNER_TEMP, 'omg-ci-artifacts-deployment.json'), JSON.stringify(receipt, null, 2));
    if (env.GITHUB_OUTPUT) appendFileSync(env.GITHUB_OUTPUT, `endpoint=${endpoint}\nsource_sha=${env.GITHUB_SHA}\n`);
    return receipt;
  } finally { rmSync(scratch, { recursive: true, force: true }); }
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  try { await deploy(); console.log('Artifact Worker source, final deployment and unauthenticated refusal verified'); }
  catch (error) {
    console.error(error instanceof DeploymentFailure ? `Artifact Worker deployment failed: ${error.message}`
      : 'Artifact Worker deployment failed; credential output suppressed');
    process.exitCode = 1;
  }
}
