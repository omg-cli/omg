import { createHash } from "node:crypto";
const digest = (value) => createHash("sha256").update(value).digest("hex");
export const rustProfile = Object.freeze({
    features: "pgp,license",
    defaultFeatures: false,
    locked: true,
    expandedFeatures: ["license", "pgp", "sequoia-openpgp"],
});
export function discoverRustTestArtifact(output, file) {
    const messages = output
        .trim()
        .split(/\r?\n/)
        .map((line) => JSON.parse(line));
    const name = file.split("/").at(-1).replace(/\.rs$/, "");
    const finishes = messages.filter((row) => row.reason === "build-finished");
    const artifacts = messages.filter(
        (row) =>
            row.reason === "compiler-artifact" &&
            row.profile?.test &&
            row.target?.name === name &&
            row.target.kind?.includes("test") &&
            row.executable,
    );
    if (
        finishes.length !== 1 ||
        finishes[0].success !== true ||
        artifacts.length !== 1 ||
        artifacts[0].target.src_path !== `/workspace/${file}` ||
        JSON.stringify(artifacts[0].features?.toSorted()) !==
            JSON.stringify(rustProfile.expandedFeatures) ||
        !/^\/workspace\/target\/[^\0\r\n]+$/.test(artifacts[0].executable) ||
        artifacts[0].executable.split("/").includes("..") ||
        !artifacts[0].package_id?.match(/#omg@/)
    )
        throw new Error(
            "Cargo did not discover exactly the expected successful OMG test executable",
        );
    return {
        executable: artifacts[0].executable,
        packageId: artifacts[0].package_id,
        target: name,
        features: artifacts[0].features,
        compilerMessagesSha256: digest(output),
    };
}
export function parseRustCatalog(output, testName) {
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(testName)) throw new Error("Invalid exact Rust test name");
    const rows = output.split(/\r?\n/).filter(Boolean);
    if (rows.length !== 1 || rows[0] !== `${testName}: test`)
        throw new Error("Regression catalog must contain exactly the executed nonignored test");
    return { testName, count: 1, sha256: digest(output) };
}
export function parseRustExecution({ stdout, stderr, exitCode, testName, file, source, catalog }) {
    if (
        Buffer.byteLength(stdout) + Buffer.byteLength(stderr) > 1024 * 1024 ||
        catalog.count !== 1 ||
        catalog.testName !== testName ||
        ![0, 101].includes(exitCode)
    )
        throw new Error("Invalid Rust execution identity or exit");
    const lines = stdout.split(/\r?\n/);
    const summaries = lines.filter((line) => /^test result:/.test(line));
    const expected = exitCode === 0 ? "ok. 1 passed; 0 failed" : "FAILED. 0 passed; 1 failed";
    const escaped = expected.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    if (
        lines.filter((line) => line === "running 1 test").length !== 1 ||
        summaries.length !== 1 ||
        !new RegExp(
            `^test result: ${escaped}; 0 ignored; 0 measured; 0 filtered out; finished in [0-9.]+s$`,
        ).test(summaries[0]) ||
        lines.filter((line) => line === `test ${testName} ... ${exitCode === 0 ? "ok" : "FAILED"}`)
            .length !== 1
    )
        throw new Error("Rust exact named terminal result was missing, skipped or conflicting");
    const result = {
        testName,
        exitCode,
        tests: 1,
        failures: exitCode === 0 ? 0 : 1,
        errors: 0,
        skipped: 0,
        reportSha256: digest(JSON.stringify({ stdout, stderr, exitCode })),
        stdoutSha256: digest(stdout),
        stderrSha256: digest(stderr),
        catalogSha256: catalog.sha256,
    };
    if (exitCode === 0) return result;
    const panics = [
        ...stderr.matchAll(
            /^thread '[^'\n]+'(?: \([1-9][0-9]*\))? panicked at ([^\n]+):(\d+):(\d+):$/gm,
        ),
    ];
    if (panics.length !== 1) throw new Error("Expected exactly one actual assertion panic");
    const [, location, lineText] = panics[0];
    const line = Number(lineText);
    const actualSourceLine = source.split(/\r?\n/)[line - 1] ?? "";
    if (
        ![file, `/workspace/${file}`].includes(location) ||
        !/^\s*assert(?:_eq|_ne)?!\s*\(/.test(actualSourceLine) ||
        !/assertion (?:`left (?:==|!=) right` failed|failed:)/.test(stderr)
    )
        throw new Error("Rust failure was setup or did not reach the designated source assertion");
    return {
        ...result,
        assertionFailure: stderr.slice(panics[0].index, panics[0].index + 4000),
        assertionFile: file,
        assertionLine: line,
        assertionSourceSha256: digest(actualSourceLine),
    };
}

export function rustReport(result, evidence) {
    const { reportSha256: previousHash, ...fields } = result;
    const content = JSON.stringify({ ...evidence, result: fields });
    return { content, result: { ...fields, reportSha256: digest(content) } };
}
