import assert from 'node:assert/strict';
import test from 'node:test';
import { imageIdentity, pinnedConfiguration, providerReady, readProviderApplication } from '../deploy.mjs';

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
