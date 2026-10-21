import { readdirSync, lstatSync, rmSync } from "node:fs";
import path from "node:path";

const dependencyRoots = new Set([
    ".ci-cargo",
    "node_modules",
    "services/subscriptions/node_modules",
    "services/ci-inspector/node_modules",
    "services/cloud-ci/node_modules",
    "services/ci-coder/node_modules",
    "experimental/electrobun/node_modules",
]);

export function pruneRestoredSource(root, trackedPaths) {
    const tracked = new Set(trackedPaths);
    const directories = new Set();

    for (const filename of tracked) {
        let directory = path.posix.dirname(filename);

        while (directory !== ".") {
            directories.add(directory);
            directory = path.posix.dirname(directory);
        }
    }

    const preservedParents = new Set(
        [...dependencyRoots].flatMap((directory) => [
            path.posix.dirname(directory),
            path.posix.dirname(path.posix.dirname(directory)),
        ]),
    );

    function visit(directory = "") {
        for (const name of readdirSync(path.join(root, directory))) {
            const relative = directory ? `${directory}/${name}` : name;

            if (dependencyRoots.has(relative) || tracked.has(relative)) continue;
            const absolute = path.join(root, relative);

            if (
                lstatSync(absolute).isDirectory() &&
                (directories.has(relative) || preservedParents.has(relative))
            )
                visit(relative);
            else rmSync(absolute, { recursive: true, force: true });
        }
    }

    visit();
}
