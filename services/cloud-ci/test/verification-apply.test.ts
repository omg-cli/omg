import { expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { mkdtemp, mkdir, writeFile, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { applyValidatedProposal } from "../runner/verification.mjs";

test("each fresh portable workspace receives only declared blob-matched patch bytes", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "codeloud-patch-"));
    const gitDirectory = path.join(root, "source");
    const workspace = path.join(root, "workspace");

    const git = (args: string[]) => {
        const result = spawnSync(
            "git",
            ["-c", "maintenance.auto=false", "-c", "gc.auto=0", "-C", gitDirectory, ...args],
            { encoding: "utf8" },
        );

        if (result.status !== 0) throw new Error(result.stderr);

        return result.stdout.trim();
    };

    try {
        for (const directory of [gitDirectory, workspace]) {
            await mkdir(path.join(directory, "src"), { recursive: true });
            await mkdir(path.join(directory, "tests"), { recursive: true });
            await writeFile(path.join(directory, "src/bug.rs"), "pub const value: u32 = 1;\n");
        }

        git(["init", "-q"]);
        git(["add", "."]);
        git(["-c", "user.name=CI", "-c", "user.email=ci@example.invalid", "commit", "-qm", "base"]);
        const baseSha = git(["rev-parse", "HEAD"]);
        const key = "b".repeat(64);
        const testPath = `tests/ai-review-${key.slice(0, 16)}-${baseSha.slice(0, 12)}.rs`;

        const change = (file: string, content: string, originalBlobSha: string | null) => ({
            path: file,
            newContent: content,
            originalBlobSha,
            oldContentQuote: originalBlobSha ? "value: u32 = 1" : "",
            sha256: createHash("sha256").update(content).digest("hex"),
        });

        const proposal = {
            repository: "omg-cli/omg",
            branch: "main",
            baseSha,
            finding: { key },
            changes: [
                change(
                    "src/bug.rs",
                    "pub const value: u32 = 2;\n",
                    git(["rev-parse", "HEAD:src/bug.rs"]),
                ),
                change(testPath, "// regression\n", null),
            ],
        };

        const context = {
            repository: proposal.repository,
            branch: proposal.branch,
            baseSha,
            workspace,
            gitDirectory,
            regression: { path: testPath },
        };

        await applyValidatedProposal(proposal, context);
        expect(await readFile(path.join(workspace, "src/bug.rs"), "utf8")).toBe(
            proposal.changes[0].newContent,
        );
        expect(await readFile(path.join(workspace, testPath), "utf8")).toBe("// regression\n");
        await writeFile(path.join(workspace, "src/bug.rs"), "tampered");

        for (const candidate of [
            proposal,
            {
                ...proposal,
                changes: [{ ...proposal.changes[0], path: "../outside.mjs" }, proposal.changes[1]],
            },
        ]) {
            let rejected = false;

            try {
                await applyValidatedProposal(candidate, context);
            } catch {
                rejected = true;
            }

            expect(rejected).toBe(true);
        }
    } finally {
        await rm(root, { recursive: true, force: true });
    }
});
