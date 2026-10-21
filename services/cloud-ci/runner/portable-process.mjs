import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import {
    chownSync,
    chmodSync,
    lstatSync,
    mkdirSync,
    readFileSync,
    readdirSync,
    readlinkSync,
} from "node:fs";
import path from "node:path";

export function portableOptions(workspace, home, env = {}) {
    return {
        cwd: workspace,
        uid: 10001,
        gid: 10001,
        detached: true,
        env: {
            PATH: "/opt/omg-python/bin:/usr/local/cargo/bin:/usr/local/bin:/usr/bin:/bin",
            HOME: home,
            TMPDIR: `${home}/tmp`,
            CI: "true",
            NO_COLOR: "1",
            CARGO_HOME: "/workspace/.ci-cargo",
            RUSTUP_HOME: "/usr/local/rustup",
            CARGO_INCREMENTAL: "0",
            CARGO_TERM_COLOR: "never",
            CARGO_BUILD_JOBS: "2",
            CARGO_PROFILE_DEV_DEBUG: "0",
            CARGO_PROFILE_TEST_DEBUG: "0",
            RUST_BACKTRACE: "0",
            PYTHONDONTWRITEBYTECODE: "1",
            // Exact protected checkout exception; temporary fixture repositories keep normal Git discovery.
            GIT_CONFIG_NOSYSTEM: "1",
            GIT_CONFIG_GLOBAL: "/dev/null",
            GIT_CONFIG_COUNT: "3",
            GIT_CONFIG_KEY_0: "maintenance.auto",
            GIT_CONFIG_VALUE_0: "false",
            GIT_CONFIG_KEY_1: "gc.auto",
            GIT_CONFIG_VALUE_1: "0",
            GIT_CONFIG_KEY_2: "safe.directory",
            GIT_CONFIG_VALUE_2: workspace,
            WRANGLER_SEND_METRICS: "false",
            CLOUDFLARE_LOAD_DEV_VARS_FROM_DOT_ENV: "false",
            ...Object.fromEntries(
                Object.entries(env).filter(([key]) =>
                    [
                        "GITHUB_RUN_ID",
                        "GITHUB_RUN_ATTEMPT",
                        "OMG_CONTRACT_SOURCE_SHA",
                        "OMG_CONTRACT_PLATFORM",
                        "OMG_CONTRACT_SURFACE_OUT",
                    ].includes(key),
                ),
            ),
        },
    };
}

function visit(root, callback) {
    const info = lstatSync(root);
    callback(root, info);

    if (info.isDirectory())
        for (const entry of readdirSync(root)) visit(path.join(root, entry), callback);
}

function fingerprint(file) {
    const info = lstatSync(file);

    if (info.isSymbolicLink()) return `link:${readlinkSync(file)}`;

    if (!info.isFile()) throw new Error("Tracked source is not a regular file or Git symlink");

    return createHash("sha256").update(readFileSync(file)).digest("hex");
}

export function preparePortable(
    workspace,
    trackedPaths,
    { home = "/tmp/omg-portable-home", protectedRoots = ["/opt/omg-ci", "/tmp/ci-source"] } = {},
) {
    if (process.platform !== "linux" || process.getuid() !== 0)
        throw new Error("Portable controller requires disposable Linux root sandbox");

    for (const root of protectedRoots)
        visit(root, (file, info) => {
            if (info.isSymbolicLink()) return;

            if (info.uid !== 0 || info.mode & 0o002 || (info.gid === 10001 && info.mode & 0o020))
                throw new Error(`Controller path is writable by candidate: ${file}`);
        });
    const source = new Map();
    const parents = new Set([workspace]);

    for (const relative of trackedPaths) {
        if (
            relative
                .split("/")
                .some((segment) => !segment || segment === "." || segment === "..") ||
            path.isAbsolute(relative)
        )
            throw new Error("Invalid tracked source path");
        const file = path.join(workspace, relative);
        source.set(file, fingerprint(file));
        const info = lstatSync(file);

        if (!info.isSymbolicLink()) {
            if (info.uid !== 0 || info.gid !== 0) chownSync(file, 0, 0);
            const mode = info.mode & 0o111 ? 0o555 : 0o444;

            if ((info.mode & 0o7777) !== mode) chmodSync(file, mode);
        }

        let parent = path.dirname(file);

        while (parent !== workspace) {
            parents.add(parent);
            parent = path.dirname(parent);
        }
    }

    for (const parent of parents) {
        if (!lstatSync(parent).isDirectory() || lstatSync(parent).isSymbolicLink())
            throw new Error("Source parent must be a real directory");
        const info = lstatSync(parent);

        if (info.uid !== 0 || info.gid !== 0) chownSync(parent, 0, 0);

        const mode = parent === workspace ? 0o1777 : 0o755;

        if ((info.mode & 0o7777) !== mode) chmodSync(parent, mode);
    }

    visit(workspace, (file, info) => {
        if (info.isSymbolicLink() || source.has(file) || parents.has(file)) return;

        if (info.uid !== 10001 || info.gid !== 10001) chownSync(file, 10001, 10001);
        const mode = info.isDirectory() ? 0o755 : info.mode & 0o111 ? 0o755 : 0o644;

        if ((info.mode & 0o7777) !== mode) chmodSync(file, mode);
    });

    for (const relative of [
        "node_modules",
        "target",
        ".ci-cargo",
        "services/cloud-ci/node_modules",
        "services/cloud-ci/dist",
        "services/cloud-ci/.wrangler",
        "services/ci-inspector/node_modules",
        "services/ci-inspector/dist",
        "services/ci-inspector/.wrangler",
        "services/ci-coder/node_modules",
        "services/ci-coder/dist",
        "services/ci-coder/.wrangler",
    ]) {
        if (trackedPaths.some((file) => file === relative || file.startsWith(`${relative}/`)))
            throw new Error("Build directory overlaps tracked source");
        const directory = path.join(workspace, relative);
        mkdirSync(directory, { recursive: true });

        if (lstatSync(directory).isSymbolicLink())
            throw new Error("Build directory must not be a symlink");
        chownSync(directory, 10001, 10001);
        chmodSync(directory, 0o755);
    }

    mkdirSync(`${home}/tmp`, { recursive: true });
    chownSync(home, 10001, 10001);
    chownSync(`${home}/tmp`, 10001, 10001);

    return {
        workspace,
        home,
        assertSource() {
            for (const [file, hash] of source)
                if (fingerprint(file) !== hash)
                    throw new Error("Portable command changed tracked source");
        },
    };
}

function candidatePids() {
    const result = [];

    for (const entry of readdirSync("/proc")) {
        if (!/^[1-9][0-9]*$/.test(entry)) continue;

        try {
            const status = readFileSync(`/proc/${entry}/status`, "utf8");

            if (/^Uid:\s+10001\s/m.test(status) && !/^State:\s+Z/m.test(status))
                result.push(Number(entry));
        } catch (error) {
            if (error.code !== "ENOENT" && error.code !== "ESRCH") throw error;
        }
    }

    return result;
}

export async function runPortable(
    context,
    command,
    args,
    env = {},
    {
        timeoutMs = 1_170_000,
        maxOutput = 8 * 1024 * 1024,
        onOutput = () => {},
        allowedExitCodes = [0],
    } = {},
) {
    if (process.platform !== "linux" || process.getuid() !== 0)
        throw new Error("Portable controller requires disposable Linux root sandbox");

    if (candidatePids().length)
        throw new Error("Candidate identity is already active; refusing shared execution");

    const child = spawn(command, args, {
        ...portableOptions(context.workspace, context.home, env),
        stdio: ["ignore", "pipe", "pipe"],
    });

    let failure;
    let bytes = 0;
    const output = { stdout: [], stderr: [] };

    const stop = () => {
        if (child.pid) {
            try {
                process.kill(-child.pid, "SIGKILL");
            } catch (error) {
                if (error.code !== "ESRCH") throw error;
            }
        }

        // This UID is reserved for one command per disposable container. Include descendants that created another session.
        for (const pid of candidatePids()) {
            try {
                process.kill(pid, "SIGSTOP");
            } catch (error) {
                if (error.code !== "ESRCH") throw error;
            }
        }

        for (const pid of candidatePids()) {
            try {
                process.kill(pid, "SIGKILL");
            } catch (error) {
                if (error.code !== "ESRCH") throw error;
            }
        }
    };

    for (const name of ["stdout", "stderr"])
        child[name].on("data", (chunk) => {
            bytes += chunk.length;

            if (bytes > maxOutput) {
                failure = new Error("Portable output exceeded byte budget");
                stop();
            } else {
                output[name].push(chunk);
                onOutput(name, chunk);
            }
        });

    const timer = setTimeout(() => {
        failure = new Error("Portable command timed out");
        stop();
    }, timeoutMs);

    try {
        const code = await new Promise((resolve, reject) => {
            child.once("error", reject);
            child.once("exit", () => stop());
            child.once("close", resolve);
        });

        if (failure) throw failure;

        if (!allowedExitCodes.includes(code)) throw new Error(`${command} exited ${code}`);

        return {
            exitCode: code,
            stdout: Buffer.concat(output.stdout).toString("utf8"),
            stderr: Buffer.concat(output.stderr).toString("utf8"),
        };
    } finally {
        clearTimeout(timer);
        stop();
        context.assertSource();
    }
}
