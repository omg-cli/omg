import { expect, test } from "bun:test";
import { mkdtemp, mkdir, writeFile, rm, symlink, unlink } from "node:fs/promises";
import path from "node:path";
import { tmpdir } from "node:os";
import { inventoryRustInputs, rustInputRoots } from "../runner/frozen-rust-inputs.mjs";

test("compiler-input inventory covers dependencies and executable bytes while excluding scratch", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "omg-frozen-inputs-"));
    try {
        for (const directory of rustInputRoots) await mkdir(path.join(root, directory), { recursive: true });
        await writeFile(path.join(root, "target/executable"), "compiled");
        await writeFile(path.join(root, ".ci-cargo/dependency"), "dependency");
        await mkdir(path.join(root, "scratch")); await writeFile(path.join(root, "scratch/value"), "scratch");
        const before = await inventoryRustInputs(root);
        expect(before.some((entry) => entry.path === path.join("target", "executable"))).toBe(true);
        expect(before.some((entry) => entry.path === path.join(".ci-cargo", "dependency"))).toBe(true);
        expect(before.some((entry) => entry.path.includes("scratch"))).toBe(false);
        await writeFile(path.join(root, "target/executable"), "changed compiled bytes");
        expect(await inventoryRustInputs(root)).not.toEqual(before);
        await mkdir(path.join(root, "node_modules/pkg"));
        await symlink(path.join(root, "node_modules/pkg"), path.join(root, "node_modules/link"), "junction");
        expect((await inventoryRustInputs(root)).some((entry) => entry.path === path.join("node_modules", "link") && entry.link)).toBe(true);
        await unlink(path.join(root, "node_modules/link"));
        await symlink(path.join(root, "scratch"), path.join(root, "node_modules/escape"), "junction");
        await expect(inventoryRustInputs(root)).rejects.toThrow("escapes immutable dependency roots");
        await unlink(path.join(root, "node_modules/escape"));
    } finally { await rm(root, { recursive: true, force: true }); }
});
