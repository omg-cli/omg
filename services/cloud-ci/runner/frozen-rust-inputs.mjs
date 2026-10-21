import { lstat, readdir, chown, chmod, realpath, readlink, lchown } from "node:fs/promises";
import path from "node:path";

export const rustInputRoots = ["target", ".ci-cargo", "node_modules", "services/cloud-ci/node_modules",
    "services/ci-inspector/node_modules", "services/ci-coder/node_modules"];

export async function inventoryRustInputs(workspace) {
    const rows = [];
    const roots = rustInputRoots.map((root) => path.resolve(workspace, root));
    const visit = async (relative) => {
        const file = path.join(workspace, relative);
        const info = await lstat(file);
        const link = info.isSymbolicLink();
        if (link) {
            const resolved = await realpath(file);
            if (!roots.some((root) => resolved === root || resolved.startsWith(`${root}${path.sep}`)))
                throw new Error("Compiler input link escapes immutable dependency roots");
        } else if (!info.isDirectory() && !info.isFile())
            throw new Error("Compiler input must be a regular file or directory");
        rows.push({ path: relative, directory: info.isDirectory(), link: link ? await readlink(file) : null, mode: info.mode & 0o7777, uid: info.uid, gid: info.gid,
            dev: info.dev, ino: info.ino, nlink: info.nlink, size: info.size, mtimeMs: info.mtimeMs });
        if (info.isDirectory())
            for (const entry of (await readdir(file)).sort()) await visit(path.join(relative, entry));
    };
    for (const root of rustInputRoots) await visit(root);
    return rows;
}

export async function freezeRustInputs(workspace) {
    if (process.platform !== "linux" || process.getuid() !== 0)
        throw new Error("Compiler input freezing requires the disposable Linux root controller");
    for (const entry of await inventoryRustInputs(workspace)) {
        const file = path.join(workspace, entry.path);
        if (entry.link) await lchown(file, 0, 0);
        else {
            await chown(file, 0, 0);
            await chmod(file, entry.directory || entry.mode & 0o111 ? 0o555 : 0o444);
        }
    }
    const expected = JSON.stringify(await inventoryRustInputs(workspace));
    return { async assertUnchanged() {
        if (JSON.stringify(await inventoryRustInputs(workspace)) !== expected)
            throw new Error("Rust listing or execution changed immutable compiler inputs");
    } };
}
