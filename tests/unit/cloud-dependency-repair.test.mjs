import assert from "node:assert/strict";
import { test } from "bun:test";
import {
    admitLockChange,
    admitAuditPair,
} from "../../scripts/cloud-dependency-repair.mjs";

const before =
    'version = 4\n\n[[package]]\nname = "example"\nversion = "0.3.1"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "' +
    "a".repeat(64) +
    '"\n\n[[package]]\nname = "other"\nversion = "1.0.0"\n';
const after = before
    .replace('version = "0.3.1"', 'version = "0.3.2"')
    .replace("a".repeat(64), "b".repeat(64));
const plan = { updates: [{ name: "example", from: "0.3.1", to: "0.3.2" }] };
const index = {
    example: [
        {
            name: "example",
            vers: "0.3.2",
            cksum: "b".repeat(64),
            yanked: false,
        },
    ],
};

test("lockfile verifier admits exact published updates and preserves unrelated packages", () => {
    assert.equal(admitLockChange(before, after, plan, index), true);
    for (const lock of [
        before,
        after.replace('version = "1.0.0"', 'version = "1.1.0"'),
        after.replace("b".repeat(64), "c".repeat(64)),
        after.slice(0, after.indexOf('name = "other"') - 13),
        after + '\n[[package]]\nname = "extra"\nversion = "1.0.0"\n',
    ])
        assert.throws(() => admitLockChange(before, lock, plan, index));
    assert.throws(() =>
        admitLockChange(before, after, plan, {
            example: [{ ...index.example[0], yanked: true }],
        }),
    );
});

test("before/after audit requires genuine findings then zero findings with unchanged database", () => {
    const baseline = {
        exitCode: 1,
        database: "d".repeat(40),
        report: {
            vulnerabilities: {
                found: true,
                count: 1,
                list: [
                    {
                        advisory: { id: "RUSTSEC-2026-0001" },
                        package: { name: "example", version: "0.3.1" },
                    },
                ],
            },
        },
    };
    const patched = {
        exitCode: 0,
        database: baseline.database,
        report: { vulnerabilities: { found: false, count: 0, list: [] } },
    };
    assert.equal(admitAuditPair(baseline, patched), true);
    for (const pair of [
        [{ ...baseline, exitCode: 2 }, patched],
        [{ ...baseline, report: {} }, patched],
        [baseline, { ...patched, database: "e".repeat(40) }],
        [baseline, { ...patched, exitCode: 1 }],
        [baseline, { ...patched, report: baseline.report }],
    ])
        assert.throws(() => admitAuditPair(...pair));
});
