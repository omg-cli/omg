import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { appendFileSync, copyFileSync, lstatSync, mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const REGISTRY_HOST = "registry.cloudflare.com";
const CREDENTIAL_TTL_MINUTES = 15;

export function credentialRequest(accountId, token, registryHost) {
    return {
        url: `https://api.cloudflare.com/client/v4/accounts/${encodeURIComponent(accountId)}/containers/registries/${encodeURIComponent(registryHost)}/credentials`,
        init: {
            method: "POST",
            redirect: "error",
            headers: {
                authorization: `Bearer ${token}`,
                "content-type": "application/json",
            },
            body: JSON.stringify({ permissions: ["pull"], expiration_minutes: CREDENTIAL_TTL_MINUTES }),
        },
    };
}

export function parseCredentials(payload, expectedHost) {
    if (payload?.success !== true) throw new Error("Registry credential request was not successful");
    const result = payload.result;
    if (!result || result.registry_host !== expectedHost)
        throw new Error("Registry credential response registry host mismatch");
    if (typeof result.username !== "string" || result.username.length === 0)
        throw new Error("Registry credential response username missing");
    if (typeof result.password !== "string" || result.password.length === 0)
        throw new Error("Registry credential response password missing");
    return { username: result.username, password: result.password, registryHost: result.registry_host };
}

export function loginArgs(registryHost, username) {
    return ["login", registryHost, "--username", username, "--password-stdin"];
}

export async function authenticate(accountId, token, registryHost, dockerConfig, {
    fetchImpl = fetch,
    spawn = spawnSync,
} = {}) {
    const { url, init } = credentialRequest(accountId, token, registryHost);
    const response = await fetchImpl(url, init);
    if (!response.ok) throw new Error(`Registry credential request failed with HTTP ${response.status}`);
    let payload;
    try {
        payload = await response.json();
    } catch {
        throw new Error("Registry credential response was not JSON");
    }
    const credentials = parseCredentials(payload, registryHost);
    const login = spawn("docker", loginArgs(registryHost, credentials.username), {
        input: credentials.password,
        env: { ...process.env, DOCKER_CONFIG: dockerConfig },
        stdio: ["pipe", "inherit", "inherit"],
    });
    if (login.error) throw new Error("Registry login could not start");
    if (login.status !== 0) throw new Error(`Registry login failed with exit ${login.status}`);
}

export function frozenInputs(root, source) {
    const runnerRoot = path.join(root, "services/cloud-ci/runner");
    const files = [];
    for (const rel of readdirSync(runnerRoot, { recursive: true })) {
        const file = path.join(runnerRoot, rel);
        const stat = lstatSync(file);
        if (stat.isDirectory()) continue;
        if (!stat.isFile()) throw new Error("Image probe runner entry is not a regular file");
        files.push({ source: `services/cloud-ci/runner/${rel}`, targets: [`/opt/omg-ci/${rel}`, `/opt/omg-ci/runner/${rel}`], sha256: createHash("sha256").update(readFileSync(file)).digest("hex") });
    }
    if (files.length === 0) throw new Error("Image probe found no frozen files");
    for (const [file, target] of [
        ["services/cloud-ci/verifier.mjs", "/opt/omg-ci/verifier.mjs"],
        ["scripts/rust-source-policy.mjs", "/scripts/rust-source-policy.mjs"],
        ["scripts/prepare-node-test-fixture.py", "/scripts/prepare-node-test-fixture.py"],
    ]) files.push({ source: file, targets: [target], sha256: createHash("sha256").update(readFileSync(path.join(root, file))).digest("hex") });
    return { source, files };
}

export function frozenAssertion({ source, files }, root = "/") {
    const script = `import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
const root = ${JSON.stringify(root)};
const files = ${JSON.stringify(files)};
for (const file of files) for (const target of file.targets)
    assert.equal(createHash("sha256").update(readFileSync(path.join(root, target))).digest("hex"), file.sha256, target);
console.log(JSON.stringify({ source: ${JSON.stringify(source)}, count: files.length }));`;
    return { script, run: `RUN --network=none ${JSON.stringify(["node", "--input-type=module", "-e", script])}` };
}

function inspectFailure(label, result) {
    const stderr = typeof result.stderr === "string" ? result.stderr : result.stderr?.toString("utf8") ?? "";
    return new Error(`Image probe ${label} failed ${JSON.stringify({ status: result.status ?? null, code: result.error?.code ?? null, signal: result.signal ?? null, stderr: stderr.slice(0, 512) })}`);
}

async function main() {
    const service = fileURLToPath(new URL("..", import.meta.url));
    const repo = path.resolve(service, "../..");
    const context = mkdtempSync(path.join(tmpdir(), "omg-image-probe-"));
    const dockerConfig = mkdtempSync(path.join(tmpdir(), "omg-image-probe-docker-"));
    const dockerEnv = { ...process.env, DOCKER_CONFIG: dockerConfig };
    try {
        const revision = spawnSync("git", ["rev-parse", "HEAD"], { cwd: repo, encoding: "utf8" });
        if (revision.status !== 0 || !/^[a-f0-9]{40}\s*$/.test(revision.stdout))
            throw new Error("Image probe requires an exact Git revision");
        const sha = revision.stdout.trim();
        const archive = spawnSync("git", ["archive", sha,
            "services/cloud-ci/runner", "services/cloud-ci/verifier.mjs", "services/cloud-ci/Dockerfile",
            "scripts/rust-source-policy.mjs", "scripts/prepare-node-test-fixture.py",
            "scripts/test_qemu_boot_diagnostics.py", "scripts/qemu-boot-diagnostics.sh",
            "scripts/benchmark-qemu.sh", "scripts/test_qemu_cloud_init_ready.py",
            "scripts/check-qemu-cloud-init.sh"],
            { cwd: repo, maxBuffer: 8 * 1024 * 1024 });
        if (archive.status !== 0) throw new Error("Image probe source archive failed");
        const extracted = spawnSync("tar", ["-x", "-C", context], { input: archive.stdout });
        if (extracted.status !== 0) throw new Error("Image probe context extraction failed");
        copyFileSync(path.join(context, "services/cloud-ci/Dockerfile"), path.join(context, "Dockerfile"));
        const from = /^FROM\s+(\S+)/m.exec(readFileSync(path.join(context, "Dockerfile"), "utf8"));
        if (!from || !from[1].startsWith(`${REGISTRY_HOST}/`))
            throw new Error(`Image probe requires a pinned ${REGISTRY_HOST} FROM image`);
        const frozen = frozenInputs(context, sha);
        appendFileSync(path.join(context, "Dockerfile"), `\n${frozenAssertion(frozen).run}\n`);
        console.log(`IMAGE_PROBE_FROZEN=${JSON.stringify({ source: sha, count: frozen.files.length })}`);
        const token = process.env.CLOUDFLARE_API_TOKEN;
        const accountId = process.env.CLOUDFLARE_ACCOUNT_ID;
        if (!token || !accountId) throw new Error("Image probe requires Workers Builds registry credentials");
        await authenticate(accountId, token, REGISTRY_HOST, dockerConfig);
        console.log(`IMAGE_PROBE_SOURCE=${sha}`);
        const build = spawnSync(process.execPath, [
            path.join(service, "node_modules/wrangler/bin/wrangler.js"),
            "containers", "build", context, "--tag", `omg-cloud-ci:${sha}`,
        ], { cwd: service, stdio: "inherit", env: dockerEnv });
        if (build.status !== 0) throw new Error(`Image probe failed with exit ${build.status}`);
        const tag = `omg-cloud-ci:${sha}`;
        const push = spawnSync(process.execPath, [path.join(service, "node_modules/wrangler/bin/wrangler.js"), "containers", "push", tag], { cwd: service, stdio: "inherit", env: dockerEnv });
        if (push.error || push.status !== 0) throw new Error(`Image probe push failed with exit ${push.status}`);
        const local = spawnSync("docker", ["image", "inspect", "--format", "{{.Id}}", tag], { encoding: "utf8", env: dockerEnv });
        if (local.error || local.status !== 0) throw inspectFailure("local image inspection", local);
        const localId = local.stdout.trim();
        if (!/^sha256:[a-f0-9]{64}$/.test(localId)) throw new Error("Image probe local image id was not exact");
        const remote = spawnSync("docker", ["manifest", "inspect", "--verbose", `${REGISTRY_HOST}/${accountId}/omg-cloud-ci:${sha}`], { encoding: "utf8", env: dockerEnv });
        if (remote.error || remote.status !== 0) throw inspectFailure("registry manifest inspection", remote);
        let manifest;
        try { manifest = JSON.parse(remote.stdout); } catch { throw new Error("Image probe registry manifest was not JSON"); }
        const configDigest = manifest?.SchemaV2Manifest?.config?.digest ?? manifest?.OCIManifest?.config?.digest;
        const manifestDigest = manifest?.Descriptor?.digest;
        const identity = spawnSync("docker", ["image", "inspect", "--format", "{{json .}}", tag], { encoding: "utf8", env: dockerEnv });
        if (identity.error || identity.status !== 0) throw inspectFailure("local identity metadata", identity);
        const image = JSON.parse(identity.stdout);
        const version = spawnSync("docker", ["version", "--format", "{{.Client.Version}}/{{.Server.Version}}"], { encoding: "utf8", env: dockerEnv });
        const driver = spawnSync("docker", ["info", "--format", "{{.Driver}}/{{json .DriverStatus}}"], { encoding: "utf8", env: dockerEnv });
        console.log(`IMAGE_PROBE_IDENTITY=${JSON.stringify({ source: sha, localId,
            localDescriptor: image.Descriptor ?? null, localRepoDigests: image.RepoDigests,
            os: image.Os, architecture: image.Architecture,
            remoteShape: Array.isArray(manifest) ? "array" : "object", remoteKeys: Object.keys(manifest),
            configDigest: configDigest ?? null, manifestDigest: manifestDigest ?? null,
            rawDigest: createHash("sha256").update(Buffer.from(manifest.Raw ?? "", "base64")).digest("hex"),
            dockerVersion: version.status === 0 ? version.stdout.trim() : null,
            driver: driver.status === 0 ? driver.stdout.trim() : null })}`);
        const linked = spawnSync("docker", ["image", "inspect", "--format", "{{json .RepoDigests}}", tag], { encoding: "utf8", env: dockerEnv });
        if (linked.error || linked.status !== 0) throw inspectFailure("local registry linkage", linked);
        validateImageIdentity({
            localId,
            image,
            manifest,
            backend: driver.status === 0 ? driver.stdout.trim() : null,
            registryReference: `${REGISTRY_HOST}/${accountId}/omg-cloud-ci`,
            repoDigests: JSON.parse(linked.stdout),
        });
        console.log(JSON.stringify({ source: sha, digest: manifestDigest, config: configDigest, count: frozen.files.length }));
    } finally {
        rmSync(dockerConfig, { recursive: true, force: true });
        rmSync(context, { recursive: true, force: true });
    }
}

const DIGEST = /^sha256:[a-f0-9]{64}$/;
const SINGLE = new Set(["application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json"]);
const LEGACY = new Set(["overlay2", "aufs", "btrfs", "devicemapper", "vfs", "zfs"]);

function digest(value, label) {
    if (typeof value !== "string" || !DIGEST.test(value)) throw new Error("Image probe " + label + " was not exact");
    return value;
}

function backendOf(driver) {
    if (typeof driver !== "string") throw new Error("Image probe storage backend evidence missing");
    if (driver.includes("io.containerd.snapshotter.v1")) return "containerd";
    if (LEGACY.has(driver.split("/", 1)[0])) return "legacy";
    throw new Error("Image probe storage backend was not recognized");
}

export function validateImageIdentity({ localId, image, manifest, backend, registryReference, repoDigests }) {
    if (!image || typeof image !== "object" || Array.isArray(image)) throw new Error("Image probe local image metadata missing");
    if (!manifest || typeof manifest !== "object" || Array.isArray(manifest)) throw new Error("Image probe registry manifest was not a single object");
    if (typeof registryReference !== "string" || !registryReference || registryReference.includes("@")) throw new Error("Image probe registry reference was not exact");
    const storage = backendOf(backend);
    digest(localId, "local image id");
    if (image.Id !== localId) throw new Error("Image probe local image metadata id mismatch");
    const remote = manifest.Descriptor;
    if (!remote || typeof remote !== "object" || Array.isArray(remote) || !SINGLE.has(remote.mediaType)) throw new Error("Image probe registry descriptor was not a single image manifest");
    const manifestDigest = digest(remote.digest, "registry manifest digest");
    const configs = [manifest.SchemaV2Manifest?.config?.digest, manifest.OCIManifest?.config?.digest].filter((value) => value !== undefined);
    if (configs.length === 0) throw new Error("Image probe registry config digest was not exact");
    const configDigest = digest(configs[0], "registry config digest");
    if (configs.some((value) => digest(value, "registry config digest") !== configDigest)) throw new Error("Image probe registry config digest mismatch");
    if (typeof manifest.Raw !== "string" || !manifest.Raw || manifest.Raw.length % 4 !== 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(manifest.Raw)) throw new Error("Image probe registry raw manifest was not base64");
    const bytes = Buffer.from(manifest.Raw, "base64");
    let raw;
    try { raw = JSON.parse(bytes.toString("utf8")); } catch { throw new Error("Image probe raw manifest was not JSON"); }
    if (!raw || typeof raw !== "object" || Array.isArray(raw) || Array.isArray(raw.manifests) || !raw.config) throw new Error("Image probe raw manifest was not a single image manifest");
    if ("sha256:" + createHash("sha256").update(bytes).digest("hex") !== manifestDigest) throw new Error("Image probe raw manifest digest mismatch");
    const rawConfig = digest(raw.config.digest, "raw manifest config digest");
    if (rawConfig !== configDigest) throw new Error("Image probe raw manifest config mismatch");
    const local = image.Descriptor;
    if (local !== undefined && local !== null) {
        if (typeof local !== "object" || Array.isArray(local) || !SINGLE.has(local.mediaType)) throw new Error("Image probe local image descriptor was not a single image manifest");
        if (digest(local.digest, "local image descriptor digest") !== manifestDigest) throw new Error("Image probe local image descriptor digest mismatch");
        if (local.annotations?.["config.digest"] !== undefined && digest(local.annotations["config.digest"], "local image descriptor config digest") !== configDigest) throw new Error("Image probe local image descriptor config mismatch");
    }
    if (storage === "containerd") {
        if (!local) throw new Error("Image probe local image descriptor missing");
        if (localId !== manifestDigest) throw new Error("Image probe containerd identity mismatch");
    } else if (localId !== configDigest) throw new Error("Image probe local image id config mismatch");
    if (!Array.isArray(repoDigests) || !repoDigests.every((value) => typeof value === "string")) throw new Error("Image probe local registry linkage was malformed");
    if (!repoDigests.includes(registryReference + "@" + manifestDigest)) throw new Error("Image probe local registry linkage missing");
    return { digest: manifestDigest, config: configDigest, repoDigest: registryReference + "@" + manifestDigest };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    if (process.env.WORKERS_CI !== "1") throw new Error("Image probe requires Workers Builds");
    await main();
}
