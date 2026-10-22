import { describe, expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { frozenAssertion, frozenInputs } from "./hosted-image-probe.mjs";

function fixture() {
    const root = mkdtempSync(path.join(tmpdir(), "omg-frozen-"));
    const installed = mkdtempSync(path.join(tmpdir(), "omg-installed-"));
    const bodies = {
        "services/cloud-ci/runner/audit-verifier.mjs": "export const audit = 1;\n",
        "services/cloud-ci/runner/runner.mjs": "export const runner = 1;\n",
        "services/cloud-ci/verifier.mjs": "export const verifier = 1;\n",
        "scripts/rust-source-policy.mjs": "export const policy = 1;\n",
        "scripts/prepare-node-test-fixture.py": "print('fixture')\n",
    };
    for (const [rel, body] of Object.entries(bodies)) {
        mkdirSync(path.dirname(path.join(root, rel)), { recursive: true });
        writeFileSync(path.join(root, rel), body);
    }
    const frozen = frozenInputs(root, "a".repeat(40));
    for (const file of frozen.files) for (const target of file.targets) {
        mkdirSync(path.dirname(path.join(installed, target)), { recursive: true });
        writeFileSync(path.join(installed, target), readFileSync(path.join(root, file.source)));
    }
    return { root, installed, frozen, assertion: frozenAssertion(frozen, installed) };
}

describe("generated frozen-input build assertion", () => {
    test("accepts both installed runner copies plus verifier and two scripts", () => {
        const { root, installed, frozen, assertion } = fixture();
        try {
            const result = spawnSync(process.execPath, ["--input-type=module", "-e", assertion.script], { encoding: "utf8" });
            expect(result.status).toBe(0);
            expect(JSON.parse(result.stdout)).toEqual({ source: "a".repeat(40), count: 5 });
        } finally {
            rmSync(root, { recursive: true, force: true });
            rmSync(installed, { recursive: true, force: true });
        }
    });

    test("rejects corruption at every installed target", () => {
        for (const target of [
            "/opt/omg-ci/audit-verifier.mjs", "/opt/omg-ci/runner/audit-verifier.mjs",
            "/opt/omg-ci/runner.mjs", "/opt/omg-ci/runner/runner.mjs",
            "/opt/omg-ci/verifier.mjs", "/scripts/rust-source-policy.mjs",
            "/scripts/prepare-node-test-fixture.py",
        ]) {
            const { root, installed, assertion } = fixture();
            try {
                writeFileSync(path.join(installed, target), "controlled changed installed bytes\n");
                const result = spawnSync(process.execPath, ["--input-type=module", "-e", assertion.script], { encoding: "utf8" });
                expect(result.status).toBe(1);
                expect(result.stderr).toContain("AssertionError");
                expect(result.stderr).toContain("ERR_ASSERTION");
                expect(result.stderr).toContain(target);
            } finally {
                rmSync(root, { recursive: true, force: true });
                rmSync(installed, { recursive: true, force: true });
            }
        }
    });
});
