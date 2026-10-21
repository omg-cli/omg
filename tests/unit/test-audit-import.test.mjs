import { test } from "bun:test";
import assert from "node:assert/strict";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { createHash } from "node:crypto";
import { importTestAuditBacklog } from "../../scripts/import-test-audit-backlog.mjs";

test("canonical backlog import preserves suite collisions and rejects changed recovered catalog bytes", async () => {
    const directory = await mkdtemp(path.join(tmpdir(), "omg-audit-import-"));
    try {
        const catalog = {
            "rust-suites": {
                lib: {
                    "package-name": "omg",
                    "binary-name": "omg_lib",
                    kind: "lib",
                    cwd: "/private/native/worktree",
                    "binary-path": "/private/native/binary",
                    testcases: {
                        "module::one": { kind: "test", ignored: false },
                        shared: { kind: "test", ignored: false },
                    },
                },
                integration: {
                    "package-name": "omg",
                    "binary-name": "integration",
                    kind: "test",
                    testcases: { shared: { kind: "test", ignored: false } },
                },
            },
        };
        const raw = JSON.stringify(catalog),
            digest = createHash("sha256").update(raw).digest("hex"),
            head = "a".repeat(40);
        const write = async (name, data) => {
            const file = path.join(directory, name);
            await writeFile(
                file,
                typeof data === "string" ? data : JSON.stringify(data),
            );
            return file;
        };
        const catalogPath = await write("catalog.json", raw);
        const remainingPath = await write("remaining.json", {
            ids: ["module::one"],
            active_unclaimed: 1,
            paused_outside_active_queue: 0,
            retired_alias_catalog_positions: 0,
        });
        const globalPath = await write("global.json", {
            source: "b".repeat(40),
            corresponding_API_head: head,
            unjoined_ids: ["module::one", "shared"],
            unjoined_names: 2,
            groups: [
                {
                    path: "artifact-123/files/execution/list.json",
                    sha256: digest,
                },
            ],
            unique_logical_names: 2,
            suite_qualified_identities: 3,
        });
        const acceptedPath = await write("accepted.json", { ids: [] });
        const catalogReceiptsPath = await write("receipts.json", [
            {
                path: catalogPath,
                artifactId: "123",
                archiveSha256: "c".repeat(64),
                catalogSha256: digest,
                run: { head_sha: head },
            },
        ]);
        const input = {
            remainingPath,
            globalPath,
            acceptedPath,
            catalogReceiptsPath,
        };
        const result = await importTestAuditBacklog(input);
        assert.equal(result.rows.length, 3);
        assert.equal(
            result.rows.filter((row) => row.testName === "shared").length,
            2,
        );
        assert.equal(result.accounting.currentExecutionCredit, 0);
        assert.equal(JSON.stringify(result).includes("/private/native"), false);
        assert.equal(result.rows[0].cohorts.includes("retained-active"), true);
        await writeFile(catalogPath, raw + " ");
        await assert.rejects(importTestAuditBacklog(input), /differs/);
    } finally {
        await rm(directory, { recursive: true, force: true });
    }
});
