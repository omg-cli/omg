import { spawnSync } from "node:child_process";
import { copyFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

if (process.env.WORKERS_CI !== "1") throw new Error("Image probe requires Workers Builds");
const service = fileURLToPath(new URL("..", import.meta.url));
const repo = path.resolve(service, "../..");
const context = mkdtempSync(path.join(tmpdir(), "omg-image-probe-"));
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
    console.log(`IMAGE_PROBE_SOURCE=${sha}`);
    const build = spawnSync(process.execPath, [
        path.join(service, "node_modules/wrangler/bin/wrangler.js"),
        "containers", "build", context, "--tag", `omg-cloud-ci:${sha}`,
    ], { cwd: service, stdio: "inherit" });
    if (build.status !== 0) throw new Error(`Image probe failed with exit ${build.status}`);
} finally {
    rmSync(context, { recursive: true, force: true });
}
