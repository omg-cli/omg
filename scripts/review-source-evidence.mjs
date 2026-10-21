import { createHash } from "node:crypto";
import { Schema } from "effect";
import { sourceReviewInputSchema } from "../services/ci-inspector/src/review-contract.ts";

export const SOURCE_REPOSITORY = "omg-cli/omg";

const exactSha = /^[a-f0-9]{40}$/;

const collection = Schema.Struct({
    sha: Schema.String,
    baseSha: Schema.String,
    branch: Schema.String,
    rawDiff: Schema.String,
    diff: Schema.String,
    numstat: Schema.String,
    blobs: Schema.instanceOf(Map),
});

export function parseSourceReviewArguments(value) {
    const args = Schema.decodeUnknownSync(Schema.Array(Schema.String))(value);
    const values = new Map();
    let snapshotOnly = false;

    for (let index = 0; index < args.length; index++) {
        const flag = args[index];

        if (flag === "--snapshot-only") {
            if (snapshotOnly) throw new Error("Duplicate snapshot-only flag.");
            snapshotOnly = true;
            continue;
        }

        if (!["--sha", "--base-sha", "--branch"].includes(flag))
            throw new Error("Unknown source review argument.");

        if (values.has(flag)) throw new Error("Duplicate source review argument.");

        values.set(flag, args[++index]);
    }

    const sha = values.get("--sha");
    const baseSha = values.get("--base-sha");
    const branch = values.get("--branch");

    if (!exactSha.test(sha ?? "") || !exactSha.test(baseSha ?? ""))
        throw new Error("Both SHA arguments must be exact lowercase 40-character Git identities.");

    if (branch !== "main") throw new Error("Target branch must be main.");

    return { sha, baseSha, branch, snapshotOnly };
}

export function sourceChanges(value) {
    const raw = Schema.decodeUnknownSync(Schema.String)(value);
    const fields = raw.split("\0");

    if (fields.pop() !== "" || fields.length === 0 || fields.length % 2 !== 0)
        throw new Error("Malformed or empty Git change inventory.");

    const changes = [];
    const seen = new Set();

    for (let index = 0; index < fields.length; index += 2) {
        const match = /^:([0-7]{6}) ([0-7]{6}) ([a-f0-9]{40}) ([a-f0-9]{40}) ([AMDT])$/.exec(
            fields[index],
        );

        const file = fields[index + 1];

        if (!match || !file || seen.has(file))
            throw new Error("Malformed or duplicate Git change entry.");

        const [, oldMode, newMode, oldBlob, newBlob, status] = match;

        if (![oldMode, newMode].every((mode) => ["000000", "100644", "100755"].includes(mode)))
            throw new Error(
                "Only regular Git files are admitted; symlinks and submodules are refused.",
            );

        if (
            status === "D"
                ? newMode !== "000000" || newBlob !== "0".repeat(40)
                : newMode === "000000" || newBlob === "0".repeat(40)
        )
            throw new Error("Invalid Git deletion identity.");

        seen.add(file);
        changes.push({ path: file, oldMode, newMode, oldBlob, newBlob, status });
    }

    if (changes.length > 30)
        throw new Error("Changed path budget exceeds 30; no coverage was truncated.");

    return changes;
}

export function isReviewSourcePath(file) {
    return /\.(?:[cm]?js|jsx|tsx?|svelte|css|html|json|ya?ml|toml|rs|py|go|cs)$/i.test(
        Schema.decodeUnknownSync(Schema.String)(file),
    );
}

export function createSourceAuditEvidence({ sha, branch, sourceFiles, runtimeEvidence }) {
    const sourceInput = sourceReviewInputSchema.parse({
        repository: SOURCE_REPOSITORY, sha, branch, changedPaths: [], diff: "",
        auditPaths: sourceFiles.map((file) => file.path), sourceFiles,
        ...(runtimeEvidence ? { runtimeEvidence } : {}),
    });
    for (const file of sourceInput.sourceFiles) {
        const bytes = Buffer.from(file.content);
        if (bytes.length > 24000 || bytes.includes(0) || createHash("sha1")
            .update(`blob ${bytes.length}\0`).update(bytes).digest("hex") !== file.blobSha)
            throw new Error("Audit source differs from exact bounded Git blob.");
    }
    return {
        repository: SOURCE_REPOSITORY, sha, baseSha: sha, branch, sourceInput,
        suppliedPaths: sourceInput.auditPaths, reviewedPaths: [], readDiff: false,
        unreviewedPaths: sourceInput.auditPaths.map((path) => ({ path, reason: "not-read-by-model" })),
        coverageMeaning: "Source audit receipts attest actual excerpts, not complete file or repository coverage.",
    };
}

export function createSourceReviewEvidence(value) {
    const input = Schema.decodeUnknownSync(collection)(value);

    parseSourceReviewArguments([
        "--sha",
        input.sha,
        "--base-sha",
        input.baseSha,
        "--branch",
        input.branch,
    ]);

    if (Buffer.byteLength(input.diff, "utf8") > 64000)
        throw new Error("Diff exceeds its 64000-byte budget; no coverage was truncated.");

    const changes = sourceChanges(input.rawDiff);
    const statistics = new Map();

    for (const entry of input.numstat.split("\0")) {
        if (!entry) continue;

        const match = /^(\d+|-)\t(\d+|-)\t(.+)$/.exec(entry);

        if (!match || statistics.has(match[3])) throw new Error("Malformed Git numstat inventory.");

        if (match[1] === "-" || match[2] === "-")
            throw new Error("Binary Git changes are refused.");

        statistics.set(match[3], true);
    }

    if (
        statistics.size !== changes.length ||
        changes.some((change) => !statistics.has(change.path))
    )
        throw new Error("Git change inventories disagree.");

    const sourceFiles = [];
    const reviewedPaths = [];
    const unreviewedPaths = [];

    for (const change of changes) {
        if (change.status === "D") {
            unreviewedPaths.push({ path: change.path, reason: "deleted-at-reviewed-commit" });
            continue;
        }

        if (!isReviewSourcePath(change.path)) {
            unreviewedPaths.push({ path: change.path, reason: "unsupported-source-type" });
            continue;
        }

        if (sourceFiles.length >= 12)
            throw new Error("Source file budget exceeds 12; no coverage was truncated.");

        const bytes = input.blobs.get(change.newBlob);

        if (!(bytes instanceof Uint8Array)) throw new Error("Missing exact Git blob bytes.");

        if (bytes.byteLength > 24000)
            throw new Error(
                "Source file is too large for the 24000-byte budget; no coverage was truncated.",
            );

        if (bytes.includes(0)) throw new Error("Binary source file is refused.");

        const actualBlob = createHash("sha1")
            .update(`blob ${bytes.byteLength}\0`)
            .update(bytes)
            .digest("hex");

        if (actualBlob !== change.newBlob) throw new Error("Git blob identity mismatch.");

        let content;

        try {
            content = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
        } catch {
            throw new Error("Binary or invalid UTF-8 source is refused.");
        }

        sourceFiles.push({ path: change.path, blobSha: actualBlob, content });
        reviewedPaths.push(change.path);
    }

    const sourceInput = sourceReviewInputSchema.parse({
        repository: SOURCE_REPOSITORY,
        sha: input.sha,
        branch: input.branch,
        changedPaths: changes.map((change) => change.path),
        diff: input.diff,
        sourceFiles,
    });

    if (Buffer.byteLength(JSON.stringify(sourceInput), "utf8") > 512 * 1024)
        throw new Error("Source request exceeds the body budget.");

    return {
        repository: SOURCE_REPOSITORY,
        sha: input.sha,
        baseSha: input.baseSha,
        branch: input.branch,
        sourceInput,
        suppliedPaths: reviewedPaths,
        reviewedPaths: [],
        unreviewedPaths: [
            ...unreviewedPaths,
            ...reviewedPaths.map((file) => ({ path: file, reason: "not-read-by-model" })),
        ],
        readDiff: false,
        coverageMeaning:
            "Read receipts attest source excerpts and touched diff chunks, not complete file or diff coverage.",
    };
}

export function sourceReviewEndpoint(value) {
    const config = Schema.decodeUnknownSync(Schema.Struct({ endpoint: Schema.String }))(value);
    const endpoint = new URL(config.endpoint);

    if (
        endpoint.protocol !== "https:" ||
        !/^omg-ci-inspector\.[a-z0-9-]+\.workers\.dev$/.test(endpoint.hostname) ||
        !["/inspect", "/review"].includes(endpoint.pathname) ||
        endpoint.search ||
        endpoint.hash ||
        endpoint.username ||
        endpoint.password ||
        endpoint.port
    )
        throw new Error("Source review requires the dedicated HTTPS inspector endpoint.");

    endpoint.pathname = "/review";

    return endpoint;
}
