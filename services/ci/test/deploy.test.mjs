import assert from 'node:assert/strict';
import test from 'node:test';
import { imageIdentity, pinnedConfiguration, providerReady, readProviderApplication, validateRuntimeSmoke } from '../deploy.mjs';

test('published image must match the tested local image and its registry digest', () => {
    const repository = 'registry.cloudflare.com/' + 'a'.repeat(32) + '/omg-native-ci';
    const digest = 'sha256:' + 'b'.repeat(64);
    const local = { Id: 'sha256:' + 'c'.repeat(64), Os: 'linux', Architecture: 'amd64', Config: { Entrypoint: ['sleep', 'infinity'] } };
    const published = { ...local, RepoDigests: [repository + '@' + digest] };
    assert.equal(imageIdentity(local, published, repository), repository + '@' + digest);
    assert.throws(() => imageIdentity(local, { ...published, Id: 'sha256:' + 'd'.repeat(64) }, repository));
    assert.throws(() => imageIdentity(local, { ...published, RepoDigests: [] }, repository));
    assert.throws(() => imageIdentity({ ...local, Config: { Entrypoint: ['node', 'server.js'] } }, published, repository));
});

test('deploy configuration pins the exact image and refuses another worker or unsafe scheduling policy', () => {
    const config = { name: 'omg-native-ci', main: 'src/index.ts', containers: [{ class_name: 'NativeRunner',
        scheduling_policy: 'default', instance_type: 'standard-4', max_instances: 1 }], vars: {} };
    const account = 'a'.repeat(32), digest = 'sha256:' + 'b'.repeat(64);
    const pinned = pinnedConfiguration(config, account, digest);
    assert.equal(pinned.vars.CI_IMAGE_DIGEST, digest);
    assert.equal(pinned.containers[0].image, `registry.cloudflare.com/${account}/omg-native-ci@${digest}`);
    assert.throws(() => pinnedConfiguration({ ...config, name: 'old-framework' }, account, digest));
    assert.throws(() => pinnedConfiguration({ ...config, containers: [{ ...config.containers[0], scheduling_policy: 'durable_object' }] }, account, digest));
    assert.throws(() => pinnedConfiguration(config, account, 'latest'));
});

test('provider admission waits for the exact image, completed rollout and idle healthy capacity', () => {
    const image = 'registry.cloudflare.com/' + 'a'.repeat(32) + '/omg-native-ci@sha256:' + 'b'.repeat(64);
    const app = { name: 'omg-native-ci-nativerunner', configuration: { image }, version: 2,
        active_rollout_id: 'rollout', health: { instances: { healthy: 1, active: 0, assigned: 0 } } };
    const rollout = { id: 'rollout', target_version: 2, target_configuration: { image }, status: 'completed' };
    assert.equal(providerReady(app, [rollout], image), true);
    assert.equal(providerReady({ ...app, health: { instances: { healthy: 0, starting: 1 } } }, [rollout], image), false);
    assert.equal(providerReady(app, [{ ...rollout, status: 'progressing' }], image), false);
    assert.equal(providerReady(app, [], image), false);
    assert.equal(providerReady({ ...app, configuration: { image: image + '-old' } }, [rollout], image), false);
    assert.equal(providerReady({ ...app, active_rollout_id: null }, [], image), true);
});

test('readiness uses fresh application detail when the list still contains the previous image', async () => {
    const image = 'registry.cloudflare.com/' + 'a'.repeat(32) + '/omg-native-ci@sha256:' + 'b'.repeat(64);
    const stale = { id: 'application', name: 'omg-native-ci-nativerunner', version: 2, configuration: { image: image + '-old' } };
    const current = { ...stale, version: 3, configuration: { image }, active_rollout_id: 'rollout', health: { instances: { healthy: 1 } } };
    const rollout = { id: 'rollout', status: 'completed', target_version: 3, target_configuration: { image } };
    const get = async suffix => suffix.startsWith('?') ? [stale] : current;
    assert.equal(providerReady(stale, [rollout], image), false);
    assert.equal(providerReady(await readProviderApplication(get), [rollout], image), true);
    await assert.rejects(readProviderApplication(async suffix => suffix.startsWith('?') ? [stale] : { ...current, id: 'another' }));
});

test('offline smoke binds successful exact tests to the baked build and independently measured artifacts', () => {
    const source = 'a'.repeat(40), hash = 'b'.repeat(64);
    const files = Object.fromEntries(['omg', 'omgd', 'libtest'].map(name => [name, { sha256: hash, bytes: 1024 }]));
    const releaseProfile = { lto: 'fat', 'codegen-units': 1, panic: 'unwind', strip: true, 'opt-level': 3, incremental: false };
    const manifest = { schemaVersion: 1, sourceSha: source, profile: 'release', features: 'debian,pgp,license',
        cargoTomlSha256: hash, compiler: 'rustc 1.95.0 (pinned)', releaseProfile, files };
    const metadata = { manifest, artifactFiles: files, releaseProfile, tests: ['exact-one', 'exact-two'],
        frozen: { 'Cargo.toml': hash }, artifactManifestSha256: hash, buildReceiptSha256: hash,
        buildReceipt: { accepted: true, sourceSha: source, candidateProcessesStopped: true,
            runtimeOnly: false, buildExecutor: 'github-actions-image-build', artifactManifestSha256: hash } };
    const result = { accepted: true, sourceSha: source, runtimeOnly: true, buildExecutor: 'github-actions-image-build',
        buildSourceSha: source, artifactManifestSha256: hash, libtestSha256: hash, candidateProcessesStopped: true,
        binaryHashes: { omg: hash, omgd: hash }, buildMetadata: { manifest, buildReceiptSha256: hash },
        tests: metadata.tests.map(name => ({ name, passed: 1, failed: 0, ignored: 0 })) };
    const output = value => 'phase output\nOMG_CI_RESULT=' + JSON.stringify(value);
    assert.deepEqual(validateRuntimeSmoke(output(result), source, metadata), result);
    assert.throws(() => validateRuntimeSmoke(output(result), source, { ...metadata,
        buildReceipt: { ...metadata.buildReceipt, buildExecutor: 'unverified' } }));
    assert.throws(() => validateRuntimeSmoke(output({ ...result, accepted: false }), source, metadata));
    assert.throws(() => validateRuntimeSmoke(output({ ...result, artifactManifestSha256: 'c'.repeat(64) }), source, metadata));
    assert.throws(() => validateRuntimeSmoke(output({ ...result, tests: [] }), source, metadata));
    assert.throws(() => validateRuntimeSmoke(output(result) + '\nOMG_CI_RESULT=' + JSON.stringify(result), source, metadata));
});
