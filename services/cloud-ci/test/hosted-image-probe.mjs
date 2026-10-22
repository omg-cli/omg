import { spawnSync } from "node:child_process";
import { copyFileSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
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
    } finally {
        rmSync(dockerConfig, { recursive: true, force: true });
        rmSync(context, { recursive: true, force: true });
    }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    if (process.env.WORKERS_CI !== "1") throw new Error("Image probe requires Workers Builds");
    await main();
}
