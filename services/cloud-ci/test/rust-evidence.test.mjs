import { expect, test } from "bun:test";
import {
    discoverRustTestArtifact,
    rustReport,
    parseRustCatalog,
    parseRustExecution,
} from "../runner/rust-evidence.mjs";
const file = "tests/ai-review-bbbbbbbbbbbbbbbb-aaaaaaaaaaaa.rs";
const source = "#[test]\nfn reproduces_defect() {\n    assert_eq!(actual(), 42);\n}\n";
const catalog = "reproduces_defect: test\n";
const passed =
    "running 1 test\ntest reproduces_defect ... ok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n";
const failed = passed
    .replace(" ... ok", " ... FAILED")
    .replace("result: ok. 1 passed; 0 failed", "result: FAILED. 0 passed; 1 failed");
const stderr = `thread 'reproduces_defect' panicked at ${file}:3:5:\nassertion \`left == right\` failed\n  left: 41\n right: 42\n`;
const parse = (stdout = passed, err = "", exitCode = 0) =>
    parseRustExecution({
        stdout,
        stderr: err,
        exitCode,
        testName: "reproduces_defect",
        file,
        source,
        catalog: parseRustCatalog(catalog, "reproduces_defect"),
    });
test("compiler discovery admits only one successful exact executable", () => {
    const artifact = {
        reason: "compiler-artifact",
        package_id: "path+file:///workspace#omg@0.1.0",
        target: {
            name: file.split("/").at(-1).slice(0, -3),
            kind: ["test"],
            src_path: `/workspace/${file}`,
        },
        features: ["license", "pgp", "sequoia-openpgp"],
        profile: { test: true },
        executable: "/workspace/target/debug/deps/repro-123",
    };
    const end = { reason: "build-finished", success: true };
    expect(
        discoverRustTestArtifact([artifact, end].map(JSON.stringify).join("\n"), file).executable,
    ).toBe(artifact.executable);
    for (const rows of [
        [artifact, artifact, end],
        [{ ...artifact, features: ["arch", "license", "pgp"] }, end],
        [
            {
                ...artifact,
                target: { ...artifact.target, src_path: "/workspace/tests/foreign.rs" },
            },
            end,
        ],
        [artifact, { ...end, success: false }],
        [{ ...artifact, target: { ...artifact.target, name: "other" } }, end],
        [{ ...artifact, executable: "/tmp/foreign" }, end],
    ])
        expect(() => discoverRustTestArtifact(rows.map(JSON.stringify).join("\n"), file)).toThrow();
});
test("exact compiler catalog and actual source assertion admit one RED or GREEN", () => {
    expect(parse().failures).toBe(0);
    expect(parse(failed, stderr, 101).assertionFailure).toContain("left: 41");
    for (const bad of [
        "",
        catalog + "other: test\n",
        catalog.replace(": test", ": benchmark"),
        catalog + catalog,
    ])
        expect(() => parseRustCatalog(bad, "reproduces_defect")).toThrow();
});
test("setup, ignored, zero, wrong-name, forged totals and nonassertion panics are not RED", () => {
    for (const [out, err, code] of [
        [
            failed,
            stderr.replace(
                "assertion `left == right` failed",
                "called Result::unwrap() on an Err value",
            ),
            101,
        ],
        [failed, stderr.replace(":3:5", ":2:5"), 101],
        [failed, stderr, 1],
        [failed, stderr.replace(file, "src/fixture.rs"), 101],
        [failed.replace("0 ignored", "1 ignored"), stderr, 101],
        [failed.replace("reproduces_defect", "other"), stderr, 101],
        [failed + failed, stderr, 101],
        [passed, "", 101],
        ["running 0 tests\n", stderr, 101],
        [failed, stderr + stderr, 101],
    ])
        expect(() => parse(out, err, code)).toThrow();
});

test("Rust 1.95 actual panic prefix includes a numeric thread ID", () => {
    expect(
        parse(failed, stderr.replace("' panicked at", "' (850) panicked at"), 101).assertionLine,
    ).toBe(3);
});

test("Rust receipt hashes exact stored raw report bytes without a self-hash cycle", async () => {
    const { mkdtemp, writeFile, readFile, rm } = await import("node:fs/promises");
    const { tmpdir } = await import("node:os");
    const { join } = await import("node:path");
    const { createHash } = await import("node:crypto");
    const directory = await mkdtemp(join(tmpdir(), "omg-rust-report-"));
    try {
        const report = rustReport(parse(), {
            artifact: { executable: "/workspace/target/test" },
            execution: { stdout: passed, stderr: "", exitCode: 0 },
        });
        await writeFile(join(directory, "patched.json"), report.content);
        const bytes = await readFile(join(directory, "patched.json"));
        expect(createHash("sha256").update(bytes).digest("hex")).toBe(report.result.reportSha256);
        expect(Object.hasOwn(JSON.parse(bytes.toString()).result, "reportSha256")).toBe(false);
    } finally {
        await rm(directory, { recursive: true, force: true });
    }
});
