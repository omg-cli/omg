import { test } from "bun:test";
import assert from "node:assert/strict";
import { mkdtemp, writeFile, mkdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { collectTestAuditPage } from "../../scripts/test-audit-inventory.mjs";

test("remaining-ledger page binds exact current blobs, holds ambiguity and paused scope, and resumes immutable cursor", async () => {
    const directory = await mkdtemp(
        path.join(tmpdir(), "omg-audit-inventory-"),
    );
    try {
        const git = (...args) =>
            execFileSync("git", args, {
                cwd: directory,
                encoding: "utf8",
            }).trim();
        git("init", "--quiet");
        await mkdir(path.join(directory, "src"));
        await writeFile(
            path.join(directory, "src/value.rs"),
            "pub fn value()->u32 {1}\n#[cfg(test)] mod tests { #[test] fn checks_value(){ assert!(value()>0); } }\n",
        );
        git("add", ".");
        const tree = git("write-tree");
        const sha = execFileSync(
            "git",
            [
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "commit-tree",
                tree,
                "-m",
                "fixture",
            ],
            { cwd: directory, encoding: "utf8" },
        ).trim();
        const manifest = {
            version: 1,
            qualification: "Historical names only; no execution credit.",
            rows: [
                {
                    id: "value::tests::checks_value",
                    cohort: "retained-active",
                    state: "pending",
                },
                {
                    id: "missing::tests::absent",
                    cohort: "global-unjoined",
                    state: "pending",
                },
                { id: "native::case", cohort: "paused", state: "held" },
            ],
        };
        const first = await collectTestAuditPage({
            sha,
            manifest,
            cursor: 0,
            pageSize: 1,
            directory,
        });
        assert.equal(first.rows[0].status, "selected");
        assert.equal(first.rows[0].task.target, "lib");
        assert.equal(first.rows[0].request.source.changedPaths.length, 0);
        assert.equal(first.rows[0].request.source.diff, "");
        assert.equal(first.executionCredit, 0);
        assert.equal(first.nextCursor, 1);
        const second = await collectTestAuditPage({
            sha,
            manifest,
            cursor: 1,
            pageSize: 2,
            directory,
            inventoryDigest: first.inventoryDigest,
        });
        assert.equal(second.rows[0].status, "held");
        assert.equal(second.rows[1].status, "held");
        assert.equal(second.nextCursor, null);
        await assert.rejects(
            collectTestAuditPage({
                sha,
                manifest: { ...manifest, qualification: "changed" },
                cursor: 1,
                directory,
                inventoryDigest: first.inventoryDigest,
            }),
            /inventory/,
        );
    } finally {
        await rm(directory, { recursive: true, force: true });
    }
});
