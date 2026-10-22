import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { copyFileSync, lstatSync, mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
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

async function main() {
    const service = fileURLToPath(new URL("..", import.meta.url));
    const repo = path.resolve(service, "../..");
    const context = mkdtempSync(path.join(tmpdir(), "omg-image-probe-"));
    const dockerConfig = mkdtempSync(path.join(tmpdir(), "omg-image-probe-docker-"));
    try {
        const revision = spawnSync("git", ["rev-parse", "HEAD"], { cwd: repo, encoding: "utf8" });
        if (revision.status !== 0 || !/^[a-f0-9]{40}\s*$/.test(revision.stdout))
            throw new Error("Image probe requires an exact Git revision");
        const sha = revision.stdout.trim();
        const archive = spawnSync("git", ["archive", sha,
            "services/cloud-ci/runner", "services/cloud-ci/verifier.mjs",
            "scripts/rust-source-policy.mjs", "scripts/prepare-node-test-fixture.py"],
            { cwd: repo, maxBuffer: 8 * 1024 * 1024 });
        if (archive.status !== 0) throw new Error("Image probe source archive failed");
        const extracted = spawnSync("tar", ["-x", "-C", context], { input: archive.stdout });
        if (extracted.status !== 0) throw new Error("Image probe context extraction failed");
        copyFileSync(path.join(service, "Dockerfile"), path.join(context, "Dockerfile"));
        const from = /^FROM\s+(\S+)/m.exec(readFileSync(path.join(context, "Dockerfile"), "utf8"));
        if (!from || !from[1].startsWith(`${REGISTRY_HOST}/`))
            throw new Error(`Image probe requires a pinned ${REGISTRY_HOST} FROM image`);
        const token = process.env.CLOUDFLARE_API_TOKEN;
        const accountId = process.env.CLOUDFLARE_ACCOUNT_ID;
        if (!token || !accountId) throw new Error("Image probe requires Workers Builds registry credentials");
        await authenticate(accountId, token, REGISTRY_HOST, dockerConfig);
        console.log(`IMAGE_PROBE_SOURCE=${sha}`);
        const build = spawnSync(process.execPath, [
            path.join(service, "node_modules/wrangler/bin/wrangler.js"),
            "containers", "build", context, "--tag", `omg-cloud-ci:${sha}`,
        ], { cwd: service, stdio: "inherit", env: { ...process.env, DOCKER_CONFIG: dockerConfig } });
        if (build.status !== 0) throw new Error(`Image probe failed with exit ${build.status}`);
        const tag = `omg-cloud-ci:${sha}`;
        const runnerRoot = path.join(context, "services/cloud-ci/runner");
        const files = [];
        for (const rel of readdirSync(runnerRoot, { recursive: true })) {
            const source = path.join(runnerRoot, rel);
            const stat = lstatSync(source);
            if (stat.isDirectory()) continue;
            if (!stat.isFile()) throw new Error("Image probe runner entry is not a regular file");
            const sha256 = createHash("sha256").update(readFileSync(source)).digest("hex");
            files.push({ source: `services/cloud-ci/runner/${rel}`, targets: [`/opt/omg-ci/${rel}`, `/opt/omg-ci/runner/${rel}`], sha256 });
        }
        if (files.length === 0) throw new Error("Image probe found no frozen files");
        for (const [source, target] of [
            ["services/cloud-ci/verifier.mjs", "/opt/omg-ci/verifier.mjs"],
            ["scripts/rust-source-policy.mjs", "/scripts/rust-source-policy.mjs"],
            ["scripts/prepare-node-test-fixture.py", "/scripts/prepare-node-test-fixture.py"],
        ]) files.push({ source, targets: [target], sha256: createHash("sha256").update(readFileSync(path.join(context, source))).digest("hex") });
        const compareScript = `import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
const files = ${JSON.stringify(files)};
for (const file of files) for (const target of file.targets)
    assert.equal(createHash("sha256").update(readFileSync(target)).digest("hex"), file.sha256, target);
console.log(JSON.stringify({ count: files.length }));`;
        const compare = spawnSync("docker", ["run", "--rm", "-i", "--network", "none", "--entrypoint", "node", tag, "--input-type=module", "-"], { input: compareScript, encoding: "utf8" });
        if (compare.error || compare.status !== 0) throw new Error("Image probe installed file comparison failed");
        let compared;
        try { compared = JSON.parse(compare.stdout); } catch { throw new Error("Image probe installed file comparison output was not JSON"); }
        if (compared?.count !== files.length) throw new Error("Image probe installed file comparison count mismatch");
        const push = spawnSync(process.execPath, [path.join(service, "node_modules/wrangler/bin/wrangler.js"), "containers", "push", tag], { cwd: service, stdio: "inherit", env: { ...process.env, DOCKER_CONFIG: dockerConfig } });
        if (push.error || push.status !== 0) throw new Error(`Image probe push failed with exit ${push.status}`);
        const local = spawnSync("docker", ["image", "inspect", "--format", "{{.Id}}", tag], { encoding: "utf8" });
        if (local.error || local.status !== 0) throw new Error("Image probe local image inspection failed");
        const localId = local.stdout.trim();
        if (!/^sha256:[a-f0-9]{64}$/.test(localId)) throw new Error("Image probe local image id was not exact");
        const remote = spawnSync("docker", ["manifest", "inspect", "--verbose", `${REGISTRY_HOST}/${accountId}/omg-cloud-ci:${sha}`], { encoding: "utf8", env: { ...process.env, DOCKER_CONFIG: dockerConfig } });
        if (remote.error || remote.status !== 0) throw new Error("Image probe registry manifest inspection failed");
        let manifest;
        try { manifest = JSON.parse(remote.stdout); } catch { throw new Error("Image probe registry manifest was not JSON"); }
        const configDigest = manifest?.SchemaV2Manifest?.config?.digest ?? manifest?.OCIManifest?.config?.digest;
        const manifestDigest = manifest?.Descriptor?.digest;
        if (configDigest !== localId) throw new Error("Image probe registry config digest mismatch");
        if (!/^sha256:[a-f0-9]{64}$/.test(manifestDigest ?? "")) throw new Error("Image probe registry manifest digest was not exact");
        const rawManifest = Buffer.from(manifest.Raw ?? "", "base64");
        if (createHash("sha256").update(rawManifest).digest("hex") !== manifestDigest.slice(7)) throw new Error("Image probe raw manifest digest mismatch");
        if (JSON.parse(rawManifest.toString("utf8"))?.config?.digest !== localId) throw new Error("Image probe raw manifest config mismatch");
        const linked = spawnSync("docker", ["image", "inspect", "--format", "{{json .RepoDigests}}", tag], { encoding: "utf8" });
        if (linked.error || linked.status !== 0 || !JSON.parse(linked.stdout).includes(`${REGISTRY_HOST}/${accountId}/omg-cloud-ci@${manifestDigest}`)) throw new Error("Image probe local registry linkage missing");
        console.log(JSON.stringify({ source: sha, digest: manifestDigest, config: configDigest, count: files.length }));
    } finally {
        rmSync(dockerConfig, { recursive: true, force: true });
        rmSync(context, { recursive: true, force: true });
    }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    if (process.env.WORKERS_CI !== "1") throw new Error("Image probe requires Workers Builds");
    await main();
}
