import assert from "node:assert/strict";
import { chownSync, mkdirSync, mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { runPortable } from "./portable-process.mjs";

if (process.platform !== "linux" || process.getuid() !== 0)
    throw new Error("Portable timeout smoke requires the disposable Linux root sandbox");

const root = mkdtempSync(path.join(os.tmpdir(), "omg-portable-timeout-smoke-"));
const workspace = path.join(root, "workspace");
const home = path.join(root, "home");

try {
    mkdirSync(workspace, { recursive: true, mode: 0o755 });
    mkdirSync(path.join(home, "tmp"), { recursive: true, mode: 0o700 });
    chownSync(root, 10001, 10001);
    chownSync(workspace, 10001, 10001);
    chownSync(home, 10001, 10001);
    chownSync(path.join(home, "tmp"), 10001, 10001);

    let sourceChecks = 0;
    const context = {
        workspace,
        home,
        assertSource() {
            sourceChecks += 1;
        },
    };

    const slash = String.fromCharCode(92);
    const octal = Array.from({ length: 32 }, (_, index) =>
        `${slash}${index.toString(8).padStart(3, "0")}`,
    ).join("");
    const controls = `printf '${octal}${slash}177'; `;
    const script = `${controls}printf '%s' 'Unicode-é-😀-𝄞-終'; printf 'OMG_STDOUT_MARKER${slash}n'; printf 'OMG_STDERR_MARKER${slash}n' >&2; sleep 30`;
    const longLabel = `timeout-smoke-${'é'.repeat(2000)}`;
    const longArgument = `arg-${'😀'.repeat(2000)}-終`;

    const timedOut = await runPortable(
        context,
        "/bin/sh",
        ["-c", script, longArgument, String.fromCharCode(1).repeat(200)],
        {},
        { timeoutMs: 3000, maxOutput: 4096, label: longLabel },
    ).then(
        () => assert.fail("portable child did not time out"),
        (error) => error,
    );

    assert.ok(
        timedOut.message.startsWith("Portable command timed out: label="),
        "timeout diagnostic must identify the command and phase label",
    );
    assert.match(timedOut.message, /timeoutMs=3000 elapsedMs=[0-9]+ bytes=[0-9]+ /);
    assert.ok(timedOut.message.includes("OMG_STDOUT_MARKER"), "timeout diagnostic lost child stdout");
    assert.ok(timedOut.message.includes("OMG_STDERR_MARKER"), "timeout diagnostic lost child stderr");
    assert.ok(
        timedOut.message.includes(`${slash}u0000`),
        "timeout diagnostic did not escape control output",
    );
    assert.ok(
        timedOut.message.includes("Unicode-é-😀-𝄞-終"),
        "timeout diagnostic lost Unicode output",
    );
    assert.ok(
        Buffer.byteLength(timedOut.message) <= 8192,
        `timeout diagnostic exceeded 8192 bytes: ${Buffer.byteLength(timedOut.message)}`,
    );
    assert.equal(sourceChecks, 1, "assertSource must run exactly once on the timeout exit");

    const cleanup = await runPortable(context, "/bin/true", [], {}, {
        timeoutMs: 10000,
        label: "cleanup-smoke",
    });
    assert.equal(cleanup.exitCode, 0, "candidate process group survived the timeout");
    assert.equal(sourceChecks, 2, "assertSource must run on every exit");
    console.log("Portable timeout diagnostics and candidate cleanup verified");
} finally {
    rmSync(root, { recursive: true, force: true });
}
