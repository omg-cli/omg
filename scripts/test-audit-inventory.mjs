import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { createHash } from "node:crypto";
const execute = promisify(execFile);
const hash = (value) => createHash("sha256").update(value).digest("hex");
const canonical = (value) =>
    JSON.stringify(value, (_, item) =>
        item && typeof item === "object" && !Array.isArray(item)
            ? Object.fromEntries(
                  Object.entries(item).sort(([a], [b]) => a.localeCompare(b)),
              )
            : item,
    );
const exact = /^[A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)*$/;

export const testAuditManifestDigest = (manifest) => hash(canonical(manifest));

export async function collectTestAuditPage({
    sha,
    manifest,
    cursor = 0,
    pageSize = 2,
    inventoryDigest,
    manifestDigest,
    directory,
}) {
    if (
        !/^[a-f0-9]{40}$/.test(sha) ||
        !Number.isSafeInteger(cursor) ||
        cursor < 0 ||
        !Number.isSafeInteger(pageSize) ||
        pageSize < 1 ||
        pageSize > 4 ||
        manifest?.version !== 1 ||
        !Array.isArray(manifest.rows) ||
        manifest.rows.length > 10000 ||
        new Set(manifest.rows.map((row) => row.id)).size !==
            manifest.rows.length ||
        manifest.rows.some(
            (row) =>
                typeof row.id !== "string" ||
                row.id.length > 600 ||
                /[\0\r\n]/.test(row.id) ||
                !exact.test(row.testName ?? row.id),
        )
    )
        throw new Error("Invalid test audit inventory");
    const git = async (args) =>
        (
            await execute("git", args, {
                cwd: directory,
                maxBuffer: 16 * 1024 * 1024,
                encoding: "utf8",
            })
        ).stdout;
    const tree = await git(["ls-tree", "-r", "-z", sha, "--", "src", "tests"]);
    const files = tree
        .split("\0")
        .filter(Boolean)
        .map((line) => {
            const m = /^(100644|100755|120000) blob ([a-f0-9]{40})\t(.+)$/.exec(
                line,
            );
            return m ? { mode: m[1], blobSha: m[2], path: m[3] } : null;
        })
        .filter(Boolean);
    const digest = hash(canonical({ sha, manifest, files }));
    if (
        (cursor > 0 && !inventoryDigest && !manifestDigest) ||
        (manifestDigest &&
            manifestDigest !== testAuditManifestDigest(manifest)) ||
        (inventoryDigest && inventoryDigest !== digest) ||
        cursor > manifest.rows.length
    )
        throw new Error("Test audit inventory changed or cursor is invalid");
    const selected = manifest.rows.slice(cursor, cursor + pageSize),
        rows = [];
    for (const row of selected) {
        const hold = (reason) => rows.push({ ...row, status: "held", reason });
        if (row.state === "held" || row.cohort === "paused") {
            hold(row.holdReason ?? "historically-paused-native-scope");
            continue;
        }
        const testName = row.testName ?? row.id;
        const name = testName.split("::").at(-1);
        let matches;
        try {
            matches = (
                await git([
                    "grep",
                    "-l",
                    "-E",
                    `(^|[^A-Za-z0-9_])fn[[:space:]]+${name}[[:space:]]*\\(`,
                    sha,
                    "--",
                    "src",
                    "tests",
                ])
            )
                .trim()
                .split(/\r?\n/)
                .filter(Boolean)
                .map((value) => value.slice(sha.length + 1));
        } catch (error) {
            if (error.code === 1) {
                hold("exact-test-source-not-found");
                continue;
            }
            throw error;
        }
        const candidates = matches.filter(
            (file) =>
                (!row.suite ||
                    (row.suite.kind === "lib" && file.startsWith("src/")) ||
                    (row.suite.kind === "test" &&
                        file === `tests/${row.suite.name}.rs`)) &&
                file.endsWith(".rs") &&
                files.some(
                    (entry) => entry.path === file && entry.mode === "100644",
                ),
        );
        if (candidates.length !== 1) {
            hold("ambiguous-or-unsupported-test-source");
            continue;
        }
        const file = files.find((entry) => entry.path === candidates[0]);
        const content = await git(["show", `${sha}:${file.path}`]);
        if (Buffer.byteLength(content) > 256 * 1024 || content.includes("\0")) {
            hold("source-exceeds-coder-snapshot-budget");
            continue;
        }
        const inline = file.path.startsWith("src/");
        if (!inline && !/^tests\/[A-Za-z0-9_-]+\.rs$/.test(file.path)) {
            hold("unsupported-cargo-target");
            continue;
        }
        const task = {
            path: file.path,
            testName,
            originalBlobSha: file.blobSha,
            ...(inline ? { target: "lib" } : {}),
        };
        rows.push({
            ...row,
            status: "selected",
            task,
            request: {
                repository: "omg-cli/omg",
                branch: "main",
                sha,
                source: {
                    repository: "omg-cli/omg",
                    branch: "main",
                    sha,
                    changedPaths: [],
                    auditPaths: [file.path],
                    diff: "",
                    sourceFiles: [
                        { path: file.path, blobSha: file.blobSha, content },
                    ],
                    ciFailures: [],
                },
                testAuditTask: task,
            },
            sourceIdentity: {
                path: file.path,
                blobSha: file.blobSha,
                sha256: hash(content),
            },
            historicalExecutionCredit: 0,
        });
    }
    return {
        kind: "test-audit",
        sha,
        inventoryDigest: digest,
        cursor,
        nextCursor:
            cursor + selected.length < manifest.rows.length
                ? cursor + selected.length
                : null,
        total: manifest.rows.length,
        rows,
        executionCredit: 0,
        partition: {
            selected: rows.filter((row) => row.status === "selected").length,
            held: rows.filter((row) => row.status === "held").length,
        },
        qualification:
            "Selection is an exact current file candidate. Only admitted four-state execution earns sensitivity credit.",
    };
}
