import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { setTimeout } from "node:timers/promises";
import {
    parseCodingRequest,
    operationIdentity,
} from "../services/ci-coder/src/request.ts";
import { admitDependencyResult } from "../services/ci-coder/src/dependency.ts";

const repository = "omg-cli/omg",
    coder = "https://omg-ci-coder.latham.workers.dev";
const hash = (value) => createHash("sha256").update(value).digest("hex");
const json = (value) => JSON.stringify(value);
const blob = (value) =>
    createHash("sha1")
        .update(`blob ${Buffer.byteLength(value)}\0`)
        .update(value)
        .digest("hex");
const packages = (content) => Bun.TOML.parse(content).package;

export function admitLockChange(original, updated, plan, index) {
    assert.notEqual(
        original,
        updated,
        "Dependency repair must change Cargo.lock",
    );
    const before = packages(original),
        after = packages(updated);
    assert.ok(Array.isArray(before) && Array.isArray(after));
    assert.equal(
        after.length,
        before.length,
        "Dependency graph expansion requires separate review",
    );
    for (const item of before) {
        const update = plan.updates.find(
            (update) =>
                update.name === item.name && update.from === item.version,
        );
        if (!update) {
            assert.deepEqual(
                after.find(
                    (candidate) =>
                        candidate.name === item.name &&
                        candidate.version === item.version,
                ),
                item,
                "Unrelated package changed",
            );
            continue;
        }
        const replacement = after.find(
            (candidate) =>
                candidate.name === item.name && candidate.version === update.to,
        );
        const published = index[item.name]?.find(
            (candidate) => candidate.vers === update.to && !candidate.yanked,
        );
        assert.ok(
            replacement && published,
            "Selected published package missing",
        );
        assert.equal(
            replacement.source,
            "registry+https://github.com/rust-lang/crates.io-index",
        );
        assert.equal(
            replacement.checksum,
            published.cksum,
            "Package checksum differs from official index",
        );
        assert.ok(
            !after.some(
                (candidate) =>
                    candidate.name === item.name &&
                    candidate.version === item.version,
            ),
            "Old reported version remains",
        );
    }
    for (const update of plan.updates)
        assert.equal(
            before.filter(
                (item) =>
                    item.name === update.name && item.version === update.from,
            ).length,
            1,
        );
    return true;
}

export function admitAuditPair(baseline, patched) {
    assert.match(baseline.database, /^[a-f0-9]{40}$/);
    assert.equal(
        baseline.database,
        patched.database,
        "Audit database changed between checks",
    );
    assert.equal(
        baseline.exitCode,
        1,
        "Baseline must fail on actual audit findings",
    );
    const old = baseline.report?.vulnerabilities,
        current = patched.report?.vulnerabilities;
    assert.equal(old?.found, true);
    assert.ok(Array.isArray(old?.list) && old.list.length > 0);
    assert.equal(old.count, old.list.length);
    assert.equal(patched.exitCode, 0);
    assert.equal(current?.found, false);
    assert.deepEqual(current?.list, []);
    assert.equal(current?.count, 0);
    return true;
}

function command(args, cwd, allowFailure = false) {
    const result = Bun.spawnSync(args, {
        cwd,
        env: process.env,
        stdout: "pipe",
        stderr: "pipe",
        timeout: 30 * 60 * 1000,
    });
    if (result.error) throw result.error;
    const stdout = result.stdout.toString(),
        stderr = result.stderr.toString();
    if (!allowFailure && result.exitCode !== 0)
        throw new Error(
            `${args[0]} ${args[1]} failed (${result.exitCode}): ${stderr.slice(-2000)}`,
        );
    return { exitCode: result.exitCode, stdout, stderr };
}

async function github(method, route, body) {
    const response = await fetch(
        `https://api.github.com/repos/${repository}${route}`,
        {
            method,
            headers: {
                Authorization: `Bearer ${process.env.GH_TOKEN}`,
                Accept: "application/vnd.github+json",
                "Content-Type": "application/json",
                "User-Agent": "omg-ci-courier/1.0",
            },
            body: body ? json(body) : undefined,
            redirect: "error",
            signal: AbortSignal.timeout(30000),
        },
    );
    if (method === "GET" && response.status === 404) return null;
    if (!response.ok)
        throw new Error(`GitHub ${method} ${route}: HTTP ${response.status}`);
    return response.json();
}

async function cloud(route, body) {
    const response = await fetch(`${coder}${route}`, {
        method: body ? "POST" : "GET",
        headers: {
            Authorization: `Bearer ${process.env.OMG_CI_CODER_TOKEN}`,
            "Content-Type": "application/json",
            "User-Agent": "omg-ci-courier/1.0",
        },
        body: body ? json(body) : undefined,
        redirect: "error",
        signal: AbortSignal.timeout(60000),
    });
    if (!response.ok) throw new Error(`Coding service HTTP ${response.status}`);
    return response.json();
}

function policy() {
    return {
        bundleSha256: process.env.OMG_CI_CODER_SKILL_BUNDLE_SHA256,
        imageDigest: process.env.OMG_CI_IMAGE_DIGEST,
        verifierRevision: process.env.OMG_CI_VERIFIER_REVISION,
    };
}
async function save(root, name, value) {
    await writeFile(
        path.join(root, name),
        typeof value === "string" ? value : json(value),
        { mode: 0o600 },
    );
}
async function document(root, name) {
    return JSON.parse(await readFile(path.join(root, name), "utf8"));
}
function audit(cwd, root, name, database, noFetch) {
    const result = command(
        [
            "cargo",
            "audit",
            "--json",
            "--db",
            database,
            ...(noFetch ? ["--no-fetch"] : []),
        ],
        cwd,
        true,
    );
    const revision = command(
        ["git", "rev-parse", "HEAD"],
        database,
    ).stdout.trim();
    const report = JSON.parse(result.stdout);
    return Promise.all([
        save(root, `${name}.stdout`, result.stdout),
        save(root, `${name}.stderr`, result.stderr),
    ]).then(() => ({ exitCode: result.exitCode, database: revision, report }));
}

async function verify(root) {
    const base = (await github("GET", "/git/ref/heads/main")).object.sha;
    assert.match(base, /^[a-f0-9]{40}$/);
    command(["git", "fetch", "--no-tags", "origin", base], process.cwd());
    const source = path.join(
        process.env.RUNNER_TEMP,
        `omg-dependency-${process.env.GITHUB_RUN_ID}`,
    );
    command(
        ["git", "worktree", "add", "--detach", source, base],
        process.cwd(),
    );
    try {
        const database = path.join(
            process.env.RUNNER_TEMP,
            "omg-dependency-advisories",
        );
        const baseline = await audit(source, root, "baseline", database, false);
        await save(root, "baseline.json", baseline);
        const findings = baseline.report?.vulnerabilities?.list;
        if (
            baseline.exitCode === 0 &&
            baseline.report?.vulnerabilities?.found === false
        ) {
            await save(root, "outcome.json", { status: "no-findings", base });
            return;
        }
        assert.equal(baseline.exitCode, 1);
        assert.ok(
            Array.isArray(findings) &&
                findings.length > 0 &&
                findings.length <= 6,
            "Bounded structured audit findings required",
        );
        const targets = [],
            index = {};
        for (const finding of findings) {
            const { name, version } = finding.package;
            assert.match(name, /^[a-z][a-z0-9_-]{0,63}$/);
            assert.match(version, /^\d+\.\d+\.\d+$/);
            const existing = targets.find((target) => target.name === name);
            if (existing) {
                assert.equal(existing.version, version);
                existing.advisories.push(finding.advisory.id);
                continue;
            }
            const prefix =
                name.length === 1
                    ? `1/${name}`
                    : name.length === 2
                      ? `2/${name}`
                      : name.length === 3
                        ? `3/${name[0]}/${name}`
                        : `${name.slice(0, 2)}/${name.slice(2, 4)}/${name}`;
            const response = await fetch(`https://index.crates.io/${prefix}`, {
                headers: { "User-Agent": "omg-cli cloud dependency CI" },
                redirect: "error",
                signal: AbortSignal.timeout(30000),
            });
            assert.equal(
                response.status,
                200,
                "Official registry index unavailable",
            );
            const versions = (await response.text())
                .trim()
                .split("\n")
                .map(JSON.parse);
            const parts = version.split(".").map(Number);
            index[name] = versions
                .filter(
                    (item) =>
                        !item.yanked &&
                        /^\d+\.\d+\.\d+$/.test(item.vers) &&
                        item.vers.split(".")[0] === String(parts[0]) &&
                        (parts[0] !== 0 ||
                            item.vers.split(".")[1] === String(parts[1])) &&
                        item.vers
                            .split(".")
                            .some(
                                (part, i, array) =>
                                    Number(part) > parts[i] &&
                                    array
                                        .slice(0, i)
                                        .every(
                                            (value, j) =>
                                                Number(value) === parts[j],
                                        ),
                            ),
                )
                .sort((a, b) => {
                    const x = a.vers.split(".").map(Number),
                        y = b.vers.split(".").map(Number);
                    return x[0] - y[0] || x[1] - y[1] || x[2] - y[2];
                })
                .slice(0, 5);
            targets.push({
                name,
                version,
                availableVersions: index[name].map((item) => item.vers),
                advisories: [finding.advisory.id],
            });
        }
        const sourceFiles = await Promise.all(
            ["Cargo.toml", "Cargo.lock"].map(async (file) => {
                const content = await readFile(path.join(source, file), "utf8");
                return { path: file, content, blobSha: blob(content) };
            }),
        );
        const request = parseCodingRequest({
            repository,
            sha: base,
            branch: "main",
            runId: process.env.GITHUB_RUN_ID,
            attempt: process.env.GITHUB_RUN_ATTEMPT,
            source: {
                repository,
                sha: base,
                branch: "main",
                changedPaths: [],
                auditPaths: sourceFiles.map((file) => file.path),
                diff: "",
                sourceFiles,
                ciFailures: [
                    {
                        job: "Dependency audit",
                        step: "cargo audit --json",
                        log: json(findings).slice(0, 8000),
                    },
                ],
            },
            dependencyTask: { targets },
        });
        const id = operationIdentity(request);
        await save(root, "request.json", request);
        await save(root, "registry.json", index);
        const started = await cloud("/operations", request);
        assert.equal(started.id, id);
        const deadline = Date.now() + 10 * 60 * 1000;
        let state;
        for (;;) {
            state = await cloud(`/operations/${id}`);
            assert.equal(state.id, id);
            if (state.status === "done") break;
            if (state.status === "unanswered" || Date.now() > deadline)
                throw new Error(
                    "Cloud dependency planning failed or exceeded ten minutes",
                );
            await setTimeout(5000);
        }
        await save(root, "cloud-result.json", state);
        const plan = admitDependencyResult(state, request, id, policy());
        for (const update of plan.updates) {
            const result = command(
                [
                    "cargo",
                    "update",
                    `${update.name}@${update.from}`,
                    "--precise",
                    update.to,
                ],
                source,
            );
            await save(
                root,
                `update-${update.name}.log`,
                result.stdout + result.stderr,
            );
        }
        assert.equal(
            command(["git", "diff", "--name-only"], source).stdout.trim(),
            "Cargo.lock",
        );
        const updated = await readFile(path.join(source, "Cargo.lock"), "utf8"),
            original = sourceFiles.find(
                (file) => file.path === "Cargo.lock",
            ).content;
        admitLockChange(original, updated, plan, index);
        await save(root, "Cargo.lock", updated);
        await save(root, "Cargo.lock.before", original);
        const metadata = command(
            [
                "cargo",
                "metadata",
                "--locked",
                "--no-deps",
                "--format-version",
                "1",
            ],
            source,
        );
        await save(root, "metadata.json", metadata.stdout);
        const patched = await audit(source, root, "patched", database, true);
        await save(root, "patched.json", patched);
        admitAuditPair(baseline, patched);
        const deny = command(
            [
                "cargo",
                "deny",
                "check",
                "advisories",
                "licenses",
                "bans",
                "sources",
            ],
            source,
            true,
        );
        await save(root, "cargo-deny.log", deny.stdout + deny.stderr);
        assert.equal(deny.exitCode, 0, "Existing cargo-deny policy must pass");
        const receipt = {
            base,
            id,
            runId: request.runId,
            attempt: request.attempt,
            controller: command(
                ["git", "rev-parse", "HEAD"],
                process.cwd(),
            ).stdout.trim(),
            database: baseline.database,
            originalSha256: hash(original),
            updatedSha256: hash(updated),
            requestSha256: hash(json(request)),
            planSha256: hash(json(plan)),
            baselineSha256: hash(
                await readFile(path.join(root, "baseline.stdout")),
            ),
            patchedSha256: hash(
                await readFile(path.join(root, "patched.stdout")),
            ),
            metadataExitCode: metadata.exitCode,
            denyExitCode: deny.exitCode,
        };
        await save(root, "receipt.json", receipt);
        await save(root, "outcome.json", { status: "verified", base, id });
        if (process.env.GITHUB_OUTPUT)
            await writeFile(process.env.GITHUB_OUTPUT, "ready=true\n", {
                flag: "a",
            });
        console.log(
            json({ status: "verified", base, id, updates: plan.updates }),
        );
    } finally {
        command(
            ["git", "worktree", "remove", "--force", source],
            process.cwd(),
        );
    }
}

async function readmit(root) {
    const receipt = await document(root, "receipt.json"),
        request = parseCodingRequest(await document(root, "request.json"));
    assert.equal(receipt.runId, process.env.GITHUB_RUN_ID);
    assert.equal(receipt.attempt, process.env.GITHUB_RUN_ATTEMPT);
    assert.equal(
        receipt.controller,
        command(["git", "rev-parse", "HEAD"], process.cwd()).stdout.trim(),
    );
    assert.equal(request.sha, receipt.base);
    assert.equal(operationIdentity(request), receipt.id);
    assert.equal(hash(json(request)), receipt.requestSha256);
    const state = await cloud(`/operations/${receipt.id}`),
        plan = admitDependencyResult(state, request, receipt.id, policy());
    assert.equal(hash(json(plan)), receipt.planSha256);
    const original = await readFile(
            path.join(root, "Cargo.lock.before"),
            "utf8",
        ),
        updated = await readFile(path.join(root, "Cargo.lock"), "utf8");
    assert.equal(hash(original), receipt.originalSha256);
    assert.equal(hash(updated), receipt.updatedSha256);
    assert.equal(
        blob(original),
        request.source.sourceFiles.find((file) => file.path === "Cargo.lock")
            .blobSha,
    );
    const baseLock = await github(
        "GET",
        `/contents/Cargo.lock?ref=${receipt.base}`,
    );
    assert.equal(baseLock.sha, blob(original));
    admitLockChange(
        original,
        updated,
        plan,
        await document(root, "registry.json"),
    );
    const baseline = await document(root, "baseline.json"),
        patched = await document(root, "patched.json");
    admitAuditPair(baseline, patched);
    for (const name of ["baseline", "patched"]) {
        const raw = await readFile(path.join(root, `${name}.stdout`), "utf8");
        assert.equal(hash(raw), receipt[`${name}Sha256`]);
        assert.deepEqual(
            JSON.parse(raw),
            (await document(root, `${name}.json`)).report,
        );
    }
    assert.equal(receipt.metadataExitCode, 0);
    assert.equal(receipt.denyExitCode, 0);
    assert.equal(
        (await github("GET", "/git/ref/heads/main")).object.sha,
        receipt.base,
        "Main changed; repair must be renewed",
    );
    return { receipt, request, state, plan, updated };
}

async function publish(root) {
    const { receipt, plan, updated } = await readmit(root);
    const branch = `ai/dependencies-${receipt.base.slice(0, 12)}-${receipt.planSha256.slice(0, 12)}`;
    const existing = await github(
        "GET",
        `/pulls?state=all&head=omg-cli:${branch}&base=main`,
    );
    if (existing.length) {
        assert.equal(existing.length, 1);
        console.log(json({ status: "existing", url: existing[0].html_url }));
        return;
    }
    const base = await github("GET", `/git/commits/${receipt.base}`);
    const createdBlob = await github("POST", "/git/blobs", {
        content: updated,
        encoding: "utf-8",
    });
    assert.equal(createdBlob.sha, blob(updated));
    const tree = await github("POST", "/git/trees", {
        base_tree: base.tree.sha,
        tree: [
            {
                path: "Cargo.lock",
                mode: "100644",
                type: "blob",
                sha: createdBlob.sha,
            },
        ],
    });
    const commit = await github("POST", "/git/commits", {
        message: `fix(deps): apply cloud-selected audit repairs\n\nCloud operation ${receipt.id}\nPlan ${receipt.planSha256}`,
        tree: tree.sha,
        parents: [receipt.base],
    });
    const previous = await github("GET", `/git/ref/heads/${branch}`);
    if (previous) {
        const old = await github("GET", `/git/commits/${previous.object.sha}`);
        assert.equal(old.tree.sha, tree.sha);
        assert.deepEqual(
            old.parents.map((parent) => parent.sha),
            [receipt.base],
        );
    } else
        await github("POST", "/git/refs", {
            ref: `refs/heads/${branch}`,
            sha: commit.sha,
        });
    assert.equal(
        (await github("GET", "/git/ref/heads/main")).object.sha,
        receipt.base,
    );
    const body = [
        "Cloudflare OpenCode selected these updates using the mandatory Potato, Ponytail, Rust and TDD skill bundle. The separate hosted verifier applied Cargo's exact resolution; the model had no GitHub write credential.",
        ...plan.updates.map(
            (update) => `- ${update.name}: ${update.from} to ${update.to}`,
        ),
        `\nEvidence: https://github.com/${repository}/actions/runs/${receipt.runId}`,
        `Cloud operation: ${receipt.id}`,
        `Advisory database: ${receipt.database}`,
        `Plan SHA256: ${receipt.planSha256}`,
        "\nExecuted: real baseline audit failure, patched audit with zero findings against the same database, cargo metadata --locked, and all existing cargo-deny policy checks. Only Cargo.lock changes. Native, QEMU, coverage and all normal PR checks still must pass. This dependency proof is not Rust test sensitivity credit. Human review and merge remain required.",
    ].join("\n");
    const pull = await github("POST", "/pulls", {
        title: "fix(deps): cloud-generated dependency audit repairs",
        body,
        head: branch,
        base: "main",
        draft: false,
    });
    assert.equal(pull.user.login, process.env.OMG_CI_PUBLISHER_LOGIN);
    assert.equal(String(pull.user.id), process.env.OMG_CI_PUBLISHER_ID);
    await save(root, "publication.json", {
        url: pull.html_url,
        number: pull.number,
        sha: previous?.object.sha ?? commit.sha,
        operation: receipt.id,
    });
    console.log(
        json({
            status: "published",
            url: pull.html_url,
            sha: previous?.object.sha ?? commit.sha,
        }),
    );
}

if (import.meta.main) {
    const [mode, directory] = process.argv.slice(2);
    assert.ok(["verify", "readmit", "publish"].includes(mode) && directory);
    assert.equal(process.env.GITHUB_REPOSITORY, repository);
    const root = path.resolve(directory);
    await mkdir(root, { recursive: true, mode: 0o700 });
    if (mode === "verify") await verify(root);
    else if (mode === "readmit") await readmit(root);
    else await publish(root);
}
