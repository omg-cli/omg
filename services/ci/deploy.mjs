import { appendFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { isDeepStrictEqual } from 'node:util';

const here = fileURLToPath(new URL('.', import.meta.url));
const root = fileURLToPath(new URL('../../', import.meta.url));
const endpoint = 'https://omg-native-ci.latham.workers.dev';
const require = (condition, message) => { if (!condition) throw new Error(message); };
const sha256 = value => createHash('sha256').update(value).digest('hex');
const files = ['services/ci/Dockerfile', 'services/ci/run.py', 'scripts/build-comparison.py', 'scripts/test-debian-daemon-catalog.py', 'rust-toolchain.toml', 'Cargo.toml'];

export function imageIdentity(local, published, repository) {
    require(local.Id === published.Id && local.Os === 'linux' && local.Architecture === 'amd64' &&
        JSON.stringify(local.Config.Entrypoint) === '["sleep","infinity"]', 'published image differs from tested image');
    const digests = published.RepoDigests.filter(value => value.startsWith(repository + '@sha256:'));
    require(digests.length === 1 && /^sha256:[a-f0-9]{64}$/.test(digests[0].split('@')[1]), 'published digest missing or ambiguous');
    return digests[0];
}

export function pinnedConfiguration(config, account, digest) {
    require(config.name === 'omg-native-ci' && config.containers?.length === 1 &&
        config.containers[0].class_name === 'NativeRunner' && config.containers[0].scheduling_policy === 'default' &&
        config.containers[0].max_instances === 1 && config.containers[0].instance_type === 'standard-4', 'unexpected CI deployment target');
    require(/^[a-f0-9]{32}$/.test(account) && /^sha256:[a-f0-9]{64}$/.test(digest), 'invalid deployment identity');
    return { ...config, account_id: account, main: path.resolve(here, config.main),
        containers: [{ ...config.containers[0], image: `registry.cloudflare.com/${account}/omg-native-ci@${digest}` }],
        vars: { ...config.vars, CI_IMAGE_DIGEST: digest } };
}

export function providerReady(application, rollouts, image) {
    const capacity = application?.health?.instances;
    if (application?.name !== 'omg-native-ci-nativerunner' || application.configuration?.image !== image ||
        !(capacity?.healthy >= 1) || (capacity.starting ?? 0) !== 0 || (capacity.scheduling ?? 0) !== 0 ||
        rollouts.some(rollout => ['pending', 'progressing'].includes(rollout.status))) return false;
    if (!application.active_rollout_id) return true;
    const active = rollouts.find(rollout => rollout.id === application.active_rollout_id);
    return active?.status === 'completed' && active.target_configuration?.image === image &&
        active.target_version === application.version;
}

export async function readProviderApplication(get) {
    const listed = await get('?name=omg-native-ci-nativerunner');
    require(Array.isArray(listed), 'provider application list is invalid');
    const applications = listed.filter(app => app.name === 'omg-native-ci-nativerunner');
    require(applications.length <= 1, 'provider application identity ambiguous');
    if (!applications.length) return undefined;
    const application = await get(`/${encodeURIComponent(applications[0].id)}`);
    require(application?.id === applications[0].id && application.name === applications[0].name,
        'provider application detail identity mismatch');
    return application;
}

export function validateRuntimeSmoke(stdout, source, metadata) {
    const lines = stdout.trim().split('\n');
    require(lines.filter(line => line.startsWith('OMG_CI_RESULT=')).length === 1 &&
        lines.at(-1).startsWith('OMG_CI_RESULT='), 'runtime smoke footer missing or ambiguous');
    const result = JSON.parse(lines.at(-1).slice('OMG_CI_RESULT='.length));
    const manifest = metadata.manifest;
    require(manifest.schemaVersion === 1 && manifest.sourceSha === source && manifest.profile === 'release' &&
        manifest.features === 'debian,pgp,license' && manifest.cargoTomlSha256 === metadata.frozen['Cargo.toml'] &&
        isDeepStrictEqual(manifest.releaseProfile, metadata.releaseProfile) &&
        manifest.compiler.startsWith('rustc 1.95.0 ') && metadata.buildReceipt.accepted === true &&
        metadata.buildReceipt.sourceSha === source && metadata.buildReceipt.candidateProcessesStopped === true &&
        metadata.buildReceipt.runtimeOnly === false && metadata.buildReceipt.buildExecutor === 'github-actions-image-build' &&
        metadata.buildReceipt.artifactManifestSha256 === metadata.artifactManifestSha256,
        'baked build identity or acceptance mismatch');
    require(isDeepStrictEqual(manifest.files, metadata.artifactFiles), 'baked artifact hashes or sizes differ');
    require(result.accepted === true && result.sourceSha === source && result.runtimeOnly === true &&
        result.buildExecutor === 'github-actions-image-build' && result.buildSourceSha === source &&
        result.artifactManifestSha256 === metadata.artifactManifestSha256 && result.libtestSha256 === manifest.files.libtest.sha256 &&
        isDeepStrictEqual(result.buildMetadata?.manifest, manifest) && result.buildMetadata.buildReceiptSha256 === metadata.buildReceiptSha256 &&
        result.candidateProcessesStopped === true &&
        ['omg', 'omgd'].every(name => result.binaryHashes?.[name] === manifest.files[name].sha256),
        'offline runtime acceptance or artifact identity mismatch');
    require(result.tests?.length === metadata.tests.length && metadata.tests.every(name => result.tests.some(test =>
        test.name === name && test.passed === 1 && test.failed === 0 && test.ignored === 0)), 'offline exact tests incomplete');
    return result;
}

export async function deploy() {
    require(process.env.GITHUB_ACTIONS === 'true' && process.env.GITHUB_REPOSITORY === 'omg-cli/omg' &&
        ['refs/heads/main', 'refs/heads/ci/plain-cloudflare'].includes(process.env.GITHUB_REF) &&
        ['push', 'workflow_dispatch'].includes(process.env.GITHUB_EVENT_NAME), 'deployment requires trusted GitHub branch');
    const account = process.env.CLOUDFLARE_ACCOUNT_ID;
    require(/^[a-f0-9]{32}$/.test(account ?? '') && process.env.CLOUDFLARE_API_TOKEN &&
        process.env.OMG_NATIVE_CI_TOKEN?.length >= 32, 'deployment credentials missing');
    const evidence = path.join(process.env.RUNNER_TEMP, 'image-proof');
    mkdirSync(evidence, { recursive: true });
    const scratch = mkdtempSync(path.join(process.env.RUNNER_TEMP || tmpdir(), 'native-ci-deploy-'));
    const proof = { schemaVersion: 1, accepted: false, commands: [], endpoint,
        documentation: ['https://developers.cloudflare.com/containers/guides/image-management/',
            'https://developers.cloudflare.com/workers/configuration/secrets/',
            'https://developers.cloudflare.com/containers/api/durable-object-container/',
            'https://developers.cloudflare.com/containers/configuration/rollouts/',
            'https://developers.cloudflare.com/api/resources/containers/subresources/applications/methods/list/',
            'https://developers.cloudflare.com/api/resources/containers/subresources/applications/methods/get/',
            'https://developers.cloudflare.com/api/resources/containers/subresources/applications/subresources/rollouts/',
            'https://rust-lang.github.io/rustup/overrides.html',
            'https://rust-lang.github.io/rustup/concepts/components.html',
            'https://docs.docker.com/build/building/multi-stage/'] };
    let container;
    const redact = value => {
        let text = value ?? '';
        for (const [name, secret] of Object.entries(process.env))
            if (/TOKEN|SECRET|PASSWORD|ACCESS_KEY/.test(name) && secret.length >= 4) text = text.replaceAll(secret, '[REDACTED]');
        return Buffer.from(text).subarray(0, 8 * 1024 * 1024);
    };
    const call = (command, args, timeout = 1200000) => {
        const started = Date.now();
        const label = String(proof.commands.length).padStart(2, '0') + '-' + path.basename(command);
        console.log(JSON.stringify({ event: 'deploy-stage-start', label, operation: args[0] }));
        const result = spawnSync(command, args, { cwd: root, encoding: 'utf8', timeout,
            maxBuffer: 8 * 1024 * 1024, env: { ...process.env, WRANGLER_SEND_METRICS: 'false', CI: 'true' } });
        const row = { label, command, operation: args[0], exitCode: result.status, elapsedMs: Date.now() - started };
        for (const name of ['stdout', 'stderr']) {
            const content = redact(result[name]);
            writeFileSync(path.join(evidence, `${label}.${name}`), content);
            row[name] = { bytes: content.length, sha256: sha256(content) };
        }
        proof.commands.push(row);
        console.log(JSON.stringify({ event: 'deploy-stage-end', label, exitCode: result.status, elapsedMs: row.elapsedMs }));
        require(result.status === 0 && !result.error, `${command} ${args[0]} failed`);
        return result.stdout.trim();
    };
    try {
        const source = call('git', ['rev-parse', 'HEAD']);
        require(/^[a-f0-9]{40}$/.test(source) && source === process.env.GITHUB_SHA, 'checkout identity mismatch');
        proof.sourceSha = source;
        proof.sourceFiles = {};
        const context = path.join(scratch, 'context');
        mkdirSync(context);
        for (const name of files) {
            const content = spawnSync('git', ['show', `${source}:${name}`], { cwd: root, maxBuffer: 1024 * 1024 });
            require(content.status === 0 && content.stdout.equals(readFileSync(path.join(root, name))), 'image source differs from commit');
            const file = path.join(context, name);
            mkdirSync(path.dirname(file), { recursive: true });
            writeFileSync(file, content.stdout);
            proof.sourceFiles[name] = sha256(content.stdout);
        }
        const tag = 'omg-native-ci:' + source;
        call('docker', ['build', '--platform', 'linux/amd64', '--build-arg', 'SOURCE_SHA=' + source,
            '--file', path.join(context, 'services/ci/Dockerfile'), '--tag', tag, context], 2700000);
        const local = JSON.parse(call('docker', ['image', 'inspect', tag]))[0];
        container = call('docker', ['create', '--network', 'none', tag]);
        call('docker', ['start', container], 30000);
        require(JSON.parse(call('docker', ['inspect', container]))[0].State.Running, 'default image entrypoint did not stay running');
        const smoke = `import apt_pkg,hashlib,json,os,pathlib,runpy,shutil,subprocess,tomllib
assert os.getuid()==0
release=dict(line.split('=',1) for line in pathlib.Path('/etc/os-release').read_text().splitlines() if '=' in line)
assert release['ID']=='ubuntu' and release['VERSION_ID'].strip('"')=='24.04'
assert all(shutil.which(name) is None for name in ('rustc','cargo','git','cc'))
apt_pkg.init(); cache=apt_pkg.Cache(None); dep=apt_pkg.DepCache(cache)
assert sum(1 for package in cache.packages if dep.get_candidate_ver(package) or package.current_ver)>=25000
assert not any(name in os.environ for name in ['CLOUDFLARE_API_TOKEN','OMG_NATIVE_CI_TOKEN','CI_TOKEN'])
frozen={name:hashlib.sha256(pathlib.Path('/opt/ci/'+name).read_bytes()).hexdigest() for name in ['run.py','build-comparison.py','test-debian-daemon-catalog.py','rust-toolchain.toml','Cargo.toml']}
artifacts=pathlib.Path('/opt/ci/artifacts'); actual={}; dependencies={}
for name in ('omg','omgd','libtest','manifest.json','build-receipt.json'):
 file=artifacts/name; status=file.stat()
 assert not file.is_symlink() and status.st_uid==0 and status.st_mode & 0o022==0
 if name in ('omg','omgd','libtest'):
  assert file.read_bytes()[:4]==bytes([127,69,76,70])
  actual[name]={'sha256':hashlib.sha256(file.read_bytes()).hexdigest(),'bytes':status.st_size}
  dependencies[name]=subprocess.check_output(['ldd',str(file)],text=True,stderr=subprocess.STDOUT)
  assert 'not found' not in dependencies[name]
manifest_bytes=(artifacts/'manifest.json').read_bytes(); build_bytes=(artifacts/'build-receipt.json').read_bytes()
print(json.dumps({'frozen':frozen,'manifest':json.loads(manifest_bytes),'buildReceipt':json.loads(build_bytes),'buildReceiptSha256':hashlib.sha256(build_bytes).hexdigest(),'artifactManifestSha256':hashlib.sha256(manifest_bytes).hexdigest(),'artifactFiles':actual,'elfDependencies':dependencies,'releaseProfile':tomllib.loads(pathlib.Path('/opt/ci/Cargo.toml').read_text())['profile']['release'],'tests':runpy.run_path('/opt/ci/build-comparison.py')['TESTS']}))`;
        const metadata = JSON.parse(call('docker', ['exec', container, '/usr/bin/python3', '-I', '-c', smoke], 60000));
        for (const name of files.slice(1)) require(metadata.frozen[path.basename(name)] === proof.sourceFiles[name], 'frozen controller image mismatch');
        writeFileSync(path.join(evidence, 'baked-artifacts.json'), JSON.stringify(metadata, null, 2));
        const runtime = call('docker', ['exec', container, '/usr/bin/python3', '-I', '/opt/ci/run.py', source], 2400000);
        proof.offlineRuntime = validateRuntimeSmoke(runtime, source, metadata);
        proof.artifactManifestSha256 = metadata.artifactManifestSha256;
        writeFileSync(path.join(evidence, 'offline-runtime-proof.json'), JSON.stringify(proof.offlineRuntime, null, 2));
        proof.bakedArtifacts = metadata;
        proof.defaultEntrypointSmoke = true;
        proof.localImageId = local.Id;
        call('docker', ['rm', '--force', container], 30000);
        container = undefined;
        const wrangler = path.join(here, 'node_modules/wrangler/bin/wrangler.js');
        call(process.execPath, [wrangler, 'containers', 'push', tag], 600000);
        const repository = `registry.cloudflare.com/${account}/omg-native-ci`;
        const published = JSON.parse(call('docker', ['image', 'inspect', `${repository}:${source}`]))[0];
        const image = imageIdentity(local, published, repository);
        proof.image = image;
        proof.imageDigest = image.split('@')[1];
        const config = pinnedConfiguration(JSON.parse(readFileSync(path.join(here, 'wrangler.jsonc'), 'utf8')), account, proof.imageDigest);
        const configPath = path.join(scratch, 'wrangler.json');
        writeFileSync(configPath, JSON.stringify(config));
        const secretPath = path.join(scratch, 'secrets.json');
        writeFileSync(secretPath, JSON.stringify({ CI_TOKEN: process.env.OMG_NATIVE_CI_TOKEN }), { mode: 0o600 });
        const deployed = call(process.execPath, [wrangler, 'deploy', '--config', configPath, '--secrets-file', secretPath], 600000);
        const version = deployed.match(/Version ID:\s*([a-f0-9-]{36})/i)?.[1];
        require(version && deployed.includes(endpoint), 'deployment output lacks expected identity');
        proof.deploymentVersion = version;
        let healthy = false;
        for (let attempt = 0; attempt < 30; attempt++) {
            try {
                const response = await fetch(endpoint + '/health', { headers: { authorization: 'Bearer ' + process.env.OMG_NATIVE_CI_TOKEN },
                    signal: AbortSignal.timeout(10000), redirect: 'error' });
                const health = await response.json();
                healthy = response.ok && health.service === 'omg-native-ci' && health.imageDigest === proof.imageDigest;
            } catch { healthy = false; }
            if (healthy) break;
            await new Promise(resolve => setTimeout(resolve, 1000));
        }
        require(healthy, 'deployed configuration health check failed');
        proof.healthConfigurationVerified = true;
        const deadline = Date.now() + 600000;
        const providerGet = async suffix => {
            const response = await fetch(`https://api.cloudflare.com/client/v4/accounts/${account}/containers/applications${suffix}`, {
                headers: { authorization: 'Bearer ' + process.env.CLOUDFLARE_API_TOKEN }, redirect: 'error',
                signal: AbortSignal.timeout(Math.max(1, Math.min(10000, deadline - Date.now()))) });
            const body = await response.text();
            require(Buffer.byteLength(body) <= 1024 * 1024, 'provider readback exceeds size limit');
            const value = JSON.parse(body);
            require(response.ok && value.success && value.result !== null && typeof value.result === 'object',
                `provider readback failed: HTTP ${response.status}`);
            require(!value.result_info?.next_page_token, 'provider readback unexpectedly paginated');
            return value.result;
        };
        proof.providerReadiness = { accepted: false, attempts: 0 };
        while (Date.now() < deadline) {
            const snapshot = { checkedAt: new Date().toISOString(), attempt: ++proof.providerReadiness.attempts };
            try {
                const application = await readProviderApplication(providerGet);
                if (application) {
                    const rollouts = await providerGet(`/${encodeURIComponent(application.id)}/rollouts`);
                    require(Array.isArray(rollouts), 'provider rollout list is invalid');
                    snapshot.application = { id: application.id, name: application.name, version: application.version,
                        image: application.configuration?.image, activeRolloutId: application.active_rollout_id,
                        instances: application.health?.instances };
                    snapshot.rollouts = rollouts.map(rollout => ({ id: rollout.id, status: rollout.status,
                        targetImage: rollout.target_configuration?.image, targetVersion: rollout.target_version }));
                    snapshot.accepted = providerReady(application, rollouts, image);
                } else snapshot.accepted = false;
            } catch (error) { snapshot.error = error.message; snapshot.accepted = false; }
            proof.providerReadiness.last = snapshot;
            writeFileSync(path.join(evidence, 'provider-readback.json'), JSON.stringify(snapshot, null, 2));
            console.log(JSON.stringify({ event: 'provider-readiness', ...snapshot }));
            if (snapshot.accepted) { proof.providerReadiness.accepted = true; break; }
            await new Promise(resolve => setTimeout(resolve, Math.max(0, Math.min(5000, deadline - Date.now()))));
        }
        require(proof.providerReadiness.accepted, 'provider image rollout or healthy capacity was not ready within ten minutes');
        proof.accepted = true;
        for (const [name, value] of Object.entries({ image_digest: proof.imageDigest, endpoint,
            deployment_version: version, source_sha: source, artifact_manifest_sha256: proof.artifactManifestSha256 }))
            appendFileSync(process.env.GITHUB_OUTPUT, `${name}=${value}\n`);
        return proof;
    } catch (error) {
        proof.error = error.message;
        throw error;
    } finally {
        if (container) {
            const result = spawnSync('docker', ['rm', '--force', container], { timeout: 30000, encoding: 'utf8' });
            proof.localContainerRemoved = result.status === 0;
        } else proof.localContainerRemoved = true;
        proof.accepted = proof.accepted && proof.localContainerRemoved;
        writeFileSync(path.join(evidence, 'ci-deployment-proof.json'), JSON.stringify(proof, null, 2));
        rmSync(scratch, { recursive: true, force: true });
    }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url))
    await deploy();
