import { readFile, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import path from "node:path";
export async function importTestAuditBacklog({
    remainingPath,
    globalPath,
    acceptedPath,
    catalogReceiptsPath,
}) {
    const read = async (file) => {
        const bytes = await readFile(file);
        if (bytes.length > 4 * 1024 * 1024)
            throw new Error("Backlog import exceeds byte budget");
        return {
            data: JSON.parse(bytes),
            provenance: {
                file: path.basename(file),
                sha256: createHash("sha256").update(bytes).digest("hex"),
            },
        };
    };
    const remaining = await read(remainingPath),
        global = await read(globalPath),
        accepted = await read(acceptedPath);
    if (
        remaining.data.ids?.length !== remaining.data.active_unclaimed ||
        global.data.unjoined_ids?.length !== global.data.unjoined_names ||
        !Array.isArray(accepted.data.ids)
    )
        throw new Error("Canonical backlog counts differ");
    const rows = new Map();
    for (const [cohort, ids] of [
        ["retained-active", remaining.data.ids],
        ["global-unjoined", global.data.unjoined_ids],
    ])
        for (const id of ids) {
            if (
                !/^[A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)*$/.test(
                    id,
                )
            )
                throw new Error("Invalid canonical logical test name");
            const prior = rows.get(id);
            if (prior) prior.cohorts.push(cohort);
            else rows.set(id, { id, cohorts: [cohort], state: "pending" });
        }
    let importedRows = [...rows.values()],
        catalogProvenance = [];
    if (catalogReceiptsPath) {
        const receipts = JSON.parse(
            await readFile(catalogReceiptsPath, "utf8"),
        );
        if (
            !Array.isArray(receipts) ||
            receipts.length !== global.data.groups.length
        )
            throw new Error("Exact pinned compiler catalog set required");
        const suites = new Map();
        for (const receipt of receipts) {
            const raw = await readFile(receipt.path.replace(/\\+/g, "/"));
            const digest = createHash("sha256").update(raw).digest("hex");
            if (
                raw.length > 4 * 1024 * 1024 ||
                digest !== receipt.catalogSha256 ||
                !global.data.groups.some(
                    (group) =>
                        group.sha256 === digest &&
                        group.path.startsWith(`artifact-${receipt.artifactId}`),
                ) ||
                receipt.run?.head_sha !== global.data.corresponding_API_head
            )
                throw new Error(
                    "Recovered compiler catalog differs from pinned historical inventory",
                );
            const catalog = JSON.parse(raw);
            for (const suite of Object.values(catalog["rust-suites"] ?? {})) {
                if (
                    suite["package-name"] !== "omg" ||
                    !["lib", "test", "bin"].includes(suite.kind) ||
                    !/^[A-Za-z0-9_-]+$/.test(suite["binary-name"])
                )
                    continue;
                for (const [name, entry] of Object.entries(
                    suite.testcases ?? {},
                )) {
                    if (!rows.has(name) || entry.kind !== "test") continue;
                    const key = `${suite.kind}:${suite["binary-name"]}#${name}`;
                    const prior = suites.get(key);
                    if (prior) {
                        prior.catalogs.push(digest);
                        prior.ignoredEverywhere &&= entry.ignored === true;
                    } else
                        suites.set(key, {
                            ...rows.get(name),
                            id: key,
                            testName: name,
                            suite: {
                                kind: suite.kind,
                                name: suite["binary-name"],
                            },
                            catalogs: [digest],
                            ignoredEverywhere: entry.ignored === true,
                        });
                }
            }
            catalogProvenance.push({
                artifactId: receipt.artifactId,
                archiveSha256: receipt.archiveSha256,
                catalogSha256: digest,
                headSha: receipt.run.head_sha,
            });
        }
        importedRows = [];
        const retired = new Set([
            ...(remaining.data.retired_alias_names ?? []),
            ...(remaining.data.retired_alias_ids ?? []),
        ]);
        for (const row of rows.values()) {
            const matches = [...suites.values()].filter(
                (suite) => suite.testName === row.id,
            );
            if (!matches.length)
                importedRows.push({
                    ...row,
                    state: "held",
                    holdReason: "historical-compiler-suite-not-found",
                });
            for (const suite of matches) {
                if (suite.suite.kind === "bin") {
                    suite.state = "held";
                    suite.holdReason = "unsupported-fixed-binary-test-target";
                } else if (retired.has(suite.testName)) {
                    suite.state = "held";
                    suite.holdReason = "historically-retired-alias";
                } else if (suite.ignoredEverywhere) {
                    suite.state = "held";
                    suite.holdReason = "historically-ignored-or-helper-case";
                }
                suite.catalogs = [...new Set(suite.catalogs)].sort();
                importedRows.push(suite);
            }
        }
    }
    return {
        version: 1,
        qualification:
            "Historical compiled names and historical acceptance references only. No current execution or native credit is inherited. Exact current source and suite discovery are required.",
        provenance: [
            remaining.provenance,
            global.provenance,
            accepted.provenance,
        ],
        catalogProvenance,
        historicalSource: global.data.source,
        accounting: {
            retainedActive: remaining.data.active_unclaimed,
            globalUnjoined: global.data.unjoined_names,
            uniqueLogicalNames: global.data.unique_logical_names,
            suiteQualifiedIdentities: global.data.suite_qualified_identities,
            unresolvedSuiteCollisionPositions: catalogReceiptsPath
                ? 0
                : global.data.suite_qualified_identities -
                  global.data.unique_logical_names,
            importedSuiteRows: importedRows.length,
            pausedCount: remaining.data.paused_outside_active_queue,
            pausedIdsAvailable: false,
            retiredAliasPositions:
                remaining.data.retired_alias_catalog_positions,
            retiredAliasNames: remaining.data.retired_alias_names,
            retiredAliasIds: remaining.data.retired_alias_ids,
            acceptedHistoricalNames: accepted.data.ids.length,
            currentExecutionCredit: 0,
        },
        rows: importedRows,
    };
}
if (import.meta.main) {
    const [
        remainingPath,
        globalPath,
        acceptedPath,
        output,
        catalogReceiptsPath,
    ] = process.argv.slice(2);
    if (!output)
        throw new Error(
            "Usage: import-test-audit-backlog remaining global accepted output",
        );
    await writeFile(
        output,
        JSON.stringify(
            await importTestAuditBacklog({
                remainingPath,
                globalPath,
                acceptedPath,
                catalogReceiptsPath,
            }),
            null,
            2,
        ) + "\n",
        { flag: "wx" },
    );
}
