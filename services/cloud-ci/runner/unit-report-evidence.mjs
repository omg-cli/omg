import {
    closeSync,
    constants,
    fstatSync,
    mkdirSync,
    openSync,
    readSync,
    rmSync,
    writeSync,
} from "node:fs";

export const unitReportPath = "/tmp/omg-ci-unit-evidence/report.xml";
export const unitReportLimit = 20_000_000;

export function candidateReportStatus(info) {
    if (!info.isFile() || info.nlink !== 1 || info.uid !== 10001) return "unsafe";

    return info.size > unitReportLimit ? "oversized" : "ready";
}

export function cleanupUnitReportEvidence(
    descriptors,
    removeReport,
    { close = closeSync, remove = rmSync, warn = console.warn } = {},
) {
    for (const descriptor of descriptors)
        if (descriptor !== undefined) {
            try {
                close(descriptor);
            } catch {
                warn(
                    JSON.stringify({
                        event: "cloud-ci-evidence-cleanup-failed",
                        operation: "close",
                    }),
                );
            }
        }
    if (removeReport) {
        try {
            remove(unitReportPath, { force: true });
        } catch {
            warn(
                JSON.stringify({ event: "cloud-ci-evidence-cleanup-failed", operation: "remove" }),
            );
        }
    }
}

export function prepareUnitReportEvidence() {
    if (process.platform !== "linux" || process.getuid() !== 0)
        throw new Error("Unit evidence requires the trusted Linux controller");
    mkdirSync("/tmp/omg-ci-unit-evidence", { mode: 0o700 });

    return {
        capture() {
            let source, target;
            let status = "unavailable";
            let bytes = 0;

            try {
                source = openSync(
                    "/tmp/codeloud-portable-units.xml",
                    constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
                );
                status = candidateReportStatus(fstatSync(source));

                if (status !== "ready") return { status, bytes: 0 };
                target = openSync(
                    unitReportPath,
                    constants.O_WRONLY |
                        constants.O_CREAT |
                        constants.O_EXCL |
                        constants.O_NOFOLLOW,
                    0o600,
                );
                const buffer = Buffer.alloc(65536);

                for (;;) {
                    const count = readSync(source, buffer, 0, buffer.length, null);

                    if (!count) break;
                    bytes += count;

                    if (bytes > unitReportLimit) return { status: "oversized", bytes: 0 };
                    let offset = 0;

                    while (offset < count)
                        offset += writeSync(target, buffer, offset, count - offset);
                }

                closeSync(target);
                target = undefined;
                status = "saved";

                return { status, bytes };
            } catch (error) {
                status = "unavailable";

                if (error.code === "ENOENT") status = "missing";

                if (error.code === "ELOOP") status = "unsafe";

                return { status, bytes: 0 };
            } finally {
                cleanupUnitReportEvidence([source, target], status !== "saved");
            }
        },
    };
}
