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
const dependencySections = ["dependencies", "dev-dependencies", "build-dependencies"];
const stableVersion = /^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/;
const comparator = /^(?:>=|<=|>|<|=)?\s*(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/;

function parseVersion(text) {
    assert.equal(typeof text, "string", "Malformed advisory range version");
    assert.match(text, stableVersion, "Malformed advisory range version");
    for (const part of text.split("."))
        assert.ok(Number.isSafeInteger(Number(part)), "Advisory range version exceeds safe integer");
    return text;
}

function parseRange(text) {
    assert.equal(typeof text, "string", "Malformed advisory range");
    assert.notEqual(text.trim(), "", "Empty advisory range");
    const parts = text.split(",").map((part) => part.trim());
    for (const part of parts) {
        assert.notEqual(part, "", "Empty advisory range comparator");
        assert.match(part, comparator, "Unsupported advisory range comparator");
        parseVersion(part.replace(/^(?:>=|<=|>|<|=)?\s*/, ""));
    }
    return parts.map((part) => part.replace(/^(>=|<=|>|<|=)\s*/, "$1")).join(" ");
}

function advisoryVersions(versions) {
    assert.ok(versions && typeof versions === "object", "Malformed advisory versions");
    assert.ok(versions.patched == null || Array.isArray(versions.patched), "Malformed advisory versions");
    assert.ok(versions.unaffected == null || Array.isArray(versions.unaffected), "Malformed advisory versions");
    assert.ok(Array.isArray(versions.patched) || Array.isArray(versions.unaffected), "Malformed advisory versions");
    const patched = versions.patched ?? [];
    const unaffected = versions.unaffected ?? [];
    for (const range of [...patched, ...unaffected]) parseRange(range);
    return { patched, unaffected };
}

export function advisorySafe(version, advisories) {
    assert.ok(Array.isArray(advisories) && advisories.length > 0, "Advisory findings required");
    const candidate = parseVersion(version);
    const checks = advisories.map((entry) => {
        assert.ok(entry && typeof entry === "object", "Malformed advisory entry");
        const { patched, unaffected } = advisoryVersions(entry.versions);
        return {
            patched: patched.map((range) => parseRange(range)),
            unaffected: unaffected.map((range) => parseRange(range)),
        };
    });
    return checks.every(
        ({ patched, unaffected }) =>
            patched.some((range) => Bun.semver.satisfies(candidate, range)) ||
            unaffected.some((range) => Bun.semver.satisfies(candidate, range)),
    );
}

export function selectCandidates(version, versions, advisories) {
    const candidate = parseVersion(version);
    const [major, minor] = candidate.split(".");
    assert.ok(Array.isArray(versions), "Malformed registry versions");
    return versions
        .filter((item) => {
            if (!item || typeof item !== "object" || !item.vers || !stableVersion.test(item.vers)) return false;
            if (item.yanked) return false;
            parseVersion(item.vers);
            const [itemMajor, itemMinor] = item.vers.split(".");
            return itemMajor === major && (major !== "0" || itemMinor === minor) && Bun.semver.order(item.vers, candidate) > 0 && advisorySafe(item.vers, advisories);
        })
        .sort((left, right) => Bun.semver.order(left.vers, right.vers))
        .slice(0, 5);
}

export function auditIgnores(config) {
    assert.ok(config && typeof config === "object", "Malformed audit configuration");
    const ignore = config.advisories?.ignore;
    assert.ok(Array.isArray(ignore), "Malformed audit ignore policy");
    for (const id of ignore)
        assert.match(id, /^RUSTSEC-[0-9]{4}-[0-9]{4}$/, "Malformed audit ignore policy");
    return new Set(ignore);
}

export function groupFindings(findings) {
    assert.ok(Array.isArray(findings), "Malformed audit findings");
    const groups = new Map();
    for (const finding of findings) {
        const { name, version } = finding.package;
        assert.match(name, /^[a-z][a-z0-9_-]{0,63}$/);
        parseVersion(version);
        const advisory = { id: finding.advisory.id, versions: finding.versions };
        const group = groups.get(name);
        if (group) {
            assert.equal(group.version, version);
            group.advisories.push(advisory);
            continue;
        }
        groups.set(name, { name, version, advisories: [advisory] });
    }
    return [...groups.values()];
}

function directDependencyNames(manifest) {
    assert.equal(typeof manifest, "string", "Cargo.toml source missing");
    const parsed = Bun.TOML.parse(manifest), names = new Set();
    assert.equal(parsed.workspace, undefined, "Workspace dependency resolution is unsupported");
    const collect = (table) => {
        if (!table || typeof table !== "object") return;
        for (const [key, value] of Object.entries(table)) names.add(value && typeof value === "object" && typeof value.package === "string" ? value.package : key);
    };
    for (const section of dependencySections) collect(parsed[section]);
    for (const target of Object.values(parsed.target ?? {})) for (const section of dependencySections) collect(target?.[section]);
    return names;
}

export function auditFindings(report, manifest, ignored = new Set()) {
    assert.ok(Array.isArray(report?.vulnerabilities?.list ?? []) && Array.isArray(report?.warnings?.unsound ?? []), "Malformed audit report");
    const direct = directDependencyNames(manifest), seen = new Set(), findings = [];
    const add = (advisory, pkg, versions, directOnly) => {
        assert.ok(advisory && typeof advisory.id === "string" && pkg && typeof pkg.name === "string" && typeof pkg.version === "string", "Malformed audit finding");
        const normalized = advisoryVersions(versions);
        if (advisory.withdrawn != null || ignored.has(advisory.id)) return;
        if (directOnly && !direct.has(pkg.name)) return;
        const key = `${advisory.id}\0${pkg.name}\0${pkg.version}`;
        if (seen.has(key)) return;
        seen.add(key);
        findings.push({ advisory, versions: normalized, package: pkg });
    };
    for (const finding of report?.vulnerabilities?.list ?? []) add(finding?.advisory, finding?.package, finding?.versions, false);
    for (const warning of report?.warnings?.unsound ?? []) if (warning?.advisory?.informational === "unsound") add(warning.advisory, warning.package, warning.versions, true);
    assert.ok(findings.length <= 6, "Bounded structured audit findings required");
    return findings;
}

export function auditHeld(report, manifest, ignored = new Set()) {
    const warnings = report?.warnings;
    if (warnings == null) return [];
    assert.ok(typeof warnings === "object", "Malformed audit warnings");
    const direct = directDependencyNames(manifest), held = [];
    for (const kind of ["unmaintained", "yanked"]) {
        const list = warnings[kind];
        if (list == null) continue;
        assert.ok(Array.isArray(list), "Malformed audit warnings");
        const active = list.filter((entry) => entry?.advisory?.withdrawn == null && !ignored.has(entry?.advisory?.id) && (kind !== "unmaintained" || direct.has(entry?.package?.name)));
        if (active.length > 0) held.push({ kind, count: active.length });
    }
    return held;
}

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

export function admitAuditPair(baseline, patched, manifest, ignored = new Set()) {
    assert.match(baseline.database, /^[a-f0-9]{40}$/);
    assert.equal(baseline.database, patched.database, "Audit database changed between checks");
    const old = baseline.report?.vulnerabilities, current = patched.report?.vulnerabilities;
    assert.ok(auditFindings(baseline.report, manifest, ignored).length > 0, "Baseline must report actionable advisories");
    if (old?.found === true) {
        assert.ok(Array.isArray(old.list) && old.list.length > 0);
        assert.equal(old.count, old.list.length);
        assert.equal(baseline.exitCode, 1);
    } else {
        assert.equal(old?.found, false);
        assert.deepEqual(old?.list, []);
        assert.equal(old?.count, 0);
        assert.equal(baseline.exitCode, 0);
    }
    assert.equal(patched.exitCode, 0);
    assert.equal(current?.found, false);
    assert.deepEqual(current?.list, []);
    assert.equal(current?.count, 0);
    assert.deepEqual(auditFindings(patched.report, manifest, ignored), [], "Patched audit must clear every actionable advisory");
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
        const manifest = await readFile(path.join(source, "Cargo.toml"), "utf8");
        const auditConfig = Bun.TOML.parse(await readFile(path.join(source, ".cargo/audit.toml"), "utf8"));
        const ignored = auditIgnores(auditConfig);
        const findings = auditFindings(baseline.report, manifest, ignored);
        if (findings.length === 0) {
            const held = auditHeld(baseline.report, manifest, ignored);
            if (held.length > 0) {
                await save(root, "outcome.json", { status: "held", reason: "unsupported-advisory-class", base, held });
                throw new Error(`Held unsupported advisory class: ${json(held)}`);
            }
            assert.equal(baseline.exitCode, 0, "Unclassified audit failure");
            assert.equal(baseline.report?.vulnerabilities?.found, false);
            assert.deepEqual(baseline.report?.vulnerabilities?.list, []);
            await save(root, "outcome.json", { status: "no-findings", base });
            return;
        }
        assert.ok(baseline.exitCode === 0 || baseline.exitCode === 1, "Baseline must report bounded actionable advisories");
        assert.ok(findings.length > 0 && findings.length <= 6, "Bounded structured audit findings required");
        const groups = groupFindings(findings);
        const targets = [], index = {};
        for (const { name, version, advisories } of groups) {
            const prefix = name.length === 1 ? `1/${name}` : name.length === 2 ? `2/${name}` : name.length === 3 ? `3/${name[0]}/${name}` : `${name.slice(0, 2)}/${name.slice(2, 4)}/${name}`;
            const response = await fetch(`https://index.crates.io/${prefix}`, { headers: { "User-Agent": "omg-cli cloud dependency CI" }, redirect: "error", signal: AbortSignal.timeout(30000) });
            assert.equal(response.status, 200, "Official registry index unavailable");
            const versions = (await response.text()).trim().split("\n").map(JSON.parse);
            index[name] = selectCandidates(version, versions, advisories);
            if (index[name].length === 0) {
                await save(root, "outcome.json", { status: "held", reason: "no-patched-candidate", base, package: name, version, advisories: advisories.map((advisory) => ({ id: advisory.id, versions: advisory.versions })) });
                throw new Error(`Held no patched candidate for ${name}@${version}`);
            }
            targets.push({ name, version, availableVersions: index[name].map((item) => item.vers), advisories: advisories.map((advisory) => advisory.id) });
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
        admitAuditPair(baseline, patched, manifest, ignored);
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
    const manifest = request.source.sourceFiles.find((file) => file.path === "Cargo.toml")?.content;
    assert.equal(typeof manifest, "string", "Cargo.toml source missing");
    const auditConfig = await github("GET", `/contents/.cargo/audit.toml?ref=${receipt.base}`);
    assert.equal(typeof auditConfig?.content, "string", "Audit ignore policy source missing");
    assert.equal(auditConfig.encoding, "base64", "Audit ignore policy encoding unsupported");
    const auditSource = Buffer.from(auditConfig.content, "base64").toString("utf8");
    assert.equal(auditConfig.sha, blob(auditSource), "Audit ignore policy differs from pinned base");
    const ignored = auditIgnores(Bun.TOML.parse(auditSource));
    const baseline = await document(root, "baseline.json"),
        patched = await document(root, "patched.json");
    admitAuditPair(baseline, patched, manifest, ignored);
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
        "\nExecuted: observed actionable findings cleared after patch, patched audit with zero vulnerabilities and zero actionable warnings against the same database, cargo metadata --locked, and all existing cargo-deny policy checks. Only Cargo.lock changes. Native, QEMU, coverage and all normal PR checks still must pass. This dependency proof is not Rust test sensitivity credit. Human review and merge remain required.",
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
