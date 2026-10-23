import assert from "node:assert/strict";
import { test } from "bun:test";

test("dependency workflow excludes non-main dispatch and untrusted audit events before secrets", async () => {
    const workflow = Bun.YAML.parse(
        await Bun.file(
            new URL("../../.github/workflows/cloud-ci.yml", import.meta.url),
        ).text(),
    );
    const allowed = new Function(
        "github",
        "inputs",
        `return (${workflow.jobs["dependency-verify"].if.replaceAll("==", "===")});`,
    );
    const github = {
        repository: "omg-cli/omg",
        ref_name: "main",
        ref: "refs/heads/main",
        event_name: "workflow_dispatch",
        event: {},
    };
    assert.equal(allowed(github, { task: "dependencies" }), true);
    assert.equal(
        allowed(
            {
                ...github,
                ref_name: "untrusted-branch",
                ref: "refs/heads/untrusted-branch",
            },
            { task: "dependencies" },
        ),
        false,
    );
    assert.equal(
        allowed(
            { ...github, repository: "other/repo" },
            { task: "dependencies" },
        ),
        false,
    );
    assert.equal(allowed(github, { task: "portable" }), false);
    assert.equal(
        allowed({ ...github, ref: "refs/tags/main" }, { task: "dependencies" }),
        false,
    );
    const run = {
        conclusion: "failure",
        event: "push",
        head_branch: "main",
        head_repository: { full_name: "omg-cli/omg" },
    };
    const audit = {
        ...github,
        event_name: "workflow_run",
        event: { workflow_run: run },
    };
    assert.equal(allowed(audit, {}), true);
    for (const change of [
        { conclusion: "success" },
        { event: "pull_request" },
        { head_branch: "fork" },
        { head_repository: { full_name: "fork/omg" } },
    ])
        assert.equal(
            allowed(
                { ...audit, event: { workflow_run: { ...run, ...change } } },
                {},
            ),
            false,
        );
});
import {
    admitLockChange,
    admitAuditPair,
    advisorySafe,
    auditFindings,
    auditHeld,
    auditIgnores,
    groupFindings,
    selectCandidates,
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
    const manifest = '[dependencies]\nexample = "0.3"\n';
    const baseline = {
        exitCode: 1,
        database: "d".repeat(40),
        report: {
            vulnerabilities: {
                found: true,
                count: 1,
                list: [{ advisory: { id: "RUSTSEC-2026-0001" }, package: { name: "example", version: "0.3.1" }, versions: { patched: [">=0.3.2"], unaffected: [] } }],
            },
        },
    };
    const patched = {
        exitCode: 0,
        database: baseline.database,
        report: { vulnerabilities: { found: false, count: 0, list: [] } },
    };
    assert.equal(admitAuditPair(baseline, patched, manifest), true);
    for (const pair of [
        [{ ...baseline, exitCode: 2 }, patched],
        [{ ...baseline, report: {} }, patched],
        [baseline, { ...patched, database: "e".repeat(40) }],
        [baseline, { ...patched, exitCode: 1 }],
        [baseline, { ...patched, report: baseline.report }],
    ])
        assert.throws(() => admitAuditPair(...pair, manifest));
});

const tokioAdvisory = { id: "RUSTSEC-2026-0386", withdrawn: null, versions: { patched: [">=1.51.6, <1.52.0", ">=1.53.3"], unaffected: ["<0.3.2"] } };
const release = (vers, yanked = false) => ({ vers, yanked });

test("candidate selection applies advisory ranges before the five-item cap", () => {
    const versions = ["1.51.0", "1.51.1", "1.51.2", "1.51.3", "1.51.4", "1.51.5", "1.51.6", "1.51.8", "1.52.0", "1.53.3", "1.53.4", "1.53.5", "1.53.6", "1.54.0", "2.0.0"].map((vers) => release(vers));
    assert.deepEqual(selectCandidates("1.50.0", versions, [tokioAdvisory]).map((item) => item.vers), ["1.51.6", "1.51.8", "1.53.3", "1.53.4", "1.53.5"]);
    assert.equal(advisorySafe("1.51.5", [tokioAdvisory]), false);
    assert.equal(advisorySafe("1.51.6", [tokioAdvisory]), true);
    assert.equal(advisorySafe("1.52.0", [tokioAdvisory]), false);
    assert.equal(advisorySafe("1.53.3", [tokioAdvisory]), true);
    assert.deepEqual(selectCandidates("1.50.0", [release("1.51.0"), release("1.51.4")], [tokioAdvisory]), []);
});

test("multiple advisories require a candidate safe for all of them", () => {
    const first = { id: "RUSTSEC-2026-0001", withdrawn: null, versions: { patched: [">=0.3.2"], unaffected: [] } };
    const second = { id: "RUSTSEC-2026-0002", withdrawn: null, versions: { patched: [">=0.3.3"], unaffected: [] } };
    assert.deepEqual(selectCandidates("0.3.1", [release("0.3.2"), release("0.3.3"), release("0.3.4")], [first, second]).map((item) => item.vers), ["0.3.3", "0.3.4"]);
});

test("withdrawn ignored and transitive findings stay explicit", () => {
    const manifest = '[dependencies]\nexample = "0.3"\n';
    const report = {
        vulnerabilities: { found: true, count: 2, list: [
            { advisory: { id: "RUSTSEC-2026-0003", withdrawn: "2026-01-01T00:00:00Z" }, package: { name: "example", version: "0.3.1" }, versions: { patched: [], unaffected: [] } },
            { advisory: { id: "RUSTSEC-2026-0004", withdrawn: null }, package: { name: "transitive", version: "1.0.0" }, versions: { patched: [], unaffected: [] } },
        ] },
        warnings: { unsound: [
            { advisory: { id: "RUSTSEC-2023-0071", informational: "unsound", withdrawn: null }, package: { name: "example", version: "0.3.1" }, versions: { patched: [], unaffected: [] } },
            { advisory: { id: "RUSTSEC-2026-0005", informational: "unsound", withdrawn: null }, package: { name: "transitive", version: "1.0.0" }, versions: { patched: [], unaffected: [] } },
        ] },
    };
    const ignored = new Set(["RUSTSEC-2023-0071"]);
    assert.deepEqual(auditFindings(report, manifest, ignored).map((finding) => finding.advisory.id), ["RUSTSEC-2026-0004"]);
    assert.deepEqual(auditHeld(report, manifest, ignored), []);
    const held = { warnings: { unmaintained: [{ advisory: { id: "RUSTSEC-2026-0006", withdrawn: null }, package: { name: "example", version: "0.3.1" } }] } };
    assert.deepEqual(auditFindings(held, manifest), []);
    assert.deepEqual(auditHeld(held, manifest), [{ kind: "unmaintained", count: 1 }]);
    assert.deepEqual(auditHeld(held, manifest, new Set(["RUSTSEC-2026-0006"])), []);
    const yanked = { warnings: { yanked: [{ advisory: { id: "RUSTSEC-2026-0007", withdrawn: null }, package: { name: "example", version: "0.3.1" } }] } };
    assert.deepEqual(auditHeld(yanked, manifest), [{ kind: "yanked", count: 1 }]);
});

test("malformed and unsupported ranges fail closed", () => {
    const advisory = (patched, unaffected = []) => ({ id: "RUSTSEC-2026-0008", withdrawn: null, versions: { patched, unaffected } });
    assert.throws(() => advisorySafe("1.0.0", [advisory([">=1.0.0, ~1.1"])]), /Unsupported advisory range comparator/);
    assert.throws(() => advisorySafe("1.0.0", [advisory(["1.0.*"])]), /Unsupported advisory range comparator/);
    assert.throws(() => advisorySafe("1.0.0", [{ id: "RUSTSEC-2026-0008", versions: {} }]), /Malformed advisory versions/);
    assert.throws(() => auditFindings({ vulnerabilities: { list: "x" } }, '[dependencies]\nexample = "0.3"\n'), /Malformed audit report/);
    assert.throws(() => auditFindings({ vulnerabilities: { list: [{}] } }, '[dependencies]\nexample = "0.3"\n'), /Malformed audit finding/);
    assert.throws(() => auditFindings({ vulnerabilities: { list: [] }, warnings: { unsound: [] } }, '[workspace]\nmembers = ["member"]\n'), /Workspace dependency resolution is unsupported/);
});

test("warning-only baseline admits only cleared actionable findings", () => {
    const manifest = '[dependencies]\ntokio = { version = "1.49" }\n';
    const baseline = { exitCode: 0, database: "d".repeat(40), report: { vulnerabilities: { found: false, count: 0, list: [] }, warnings: { unsound: [{ advisory: { id: "RUSTSEC-2026-0386", informational: "unsound", withdrawn: null }, package: { name: "tokio", version: "1.50.0" }, versions: tokioAdvisory.versions }] } } };
    const patched = { exitCode: 0, database: baseline.database, report: { vulnerabilities: { found: false, count: 0, list: [] }, warnings: { unsound: [] } } };
    assert.equal(admitAuditPair(baseline, patched, manifest), true);
    assert.throws(() => admitAuditPair(baseline, { ...patched, report: baseline.report }, manifest));
    assert.throws(() => admitAuditPair({ ...baseline, report: { vulnerabilities: { found: false, count: 0, list: [] }, warnings: { unmaintained: [{ advisory: { id: "RUSTSEC-2026-0009", withdrawn: null }, package: { name: "tokio", version: "1.50.0" } }] } } }, patched, manifest));
});

test("actual cargo-audit envelope carries sibling versions through grouping and selection", () => {
    const manifest = '[dependencies]\ntokio = { version = "1.49" }\n';
    const report = {
        vulnerabilities: { found: false, count: 0, list: [] },
        warnings: { unsound: [{
            kind: "unsound",
            package: { name: "tokio", version: "1.50.0" },
            advisory: { id: "RUSTSEC-2026-0386", package: "tokio", informational: "unsound", withdrawn: null },
            versions: { patched: [">=1.51.6, <1.52.0", ">=1.53.3"], unaffected: ["<0.3.2"] },
        }] },
    };
    const findings = auditFindings(report, manifest);
    assert.deepEqual(findings[0].versions, { patched: [">=1.51.6, <1.52.0", ">=1.53.3"], unaffected: ["<0.3.2"] });
    const groups = groupFindings(findings);
    const versions = ["1.51.5", "1.51.6", "1.52.0", "1.53.3", "1.54.0"].map((vers) => release(vers));
    assert.deepEqual(selectCandidates("1.50.0", versions, groups[0].advisories).map((item) => item.vers), ["1.51.6", "1.53.3", "1.54.0"]);
});

test("candidate and range validation rejects unsafe or unsupported input before short circuit", () => {
    const entry = (patched, unaffected = []) => ({ id: "RUSTSEC-2026-0008", versions: { patched, unaffected } });
    assert.throws(() => selectCandidates("1.x.0", [release("1.1.0")], [entry([">=1.0.0"])]), /Malformed advisory range version/);
    assert.throws(() => advisorySafe("1.0.0", [entry([">=9007199254740992.0.0"])]), /safe integer/);
    assert.throws(() => selectCandidates("1.0.0", [release("9007199254740992.0.0")], [entry([">=1.0.0"])]), /safe integer/);
    assert.throws(() => advisorySafe("1.51.6", [entry([">=1.51.6", ">=1.52.0, ~1.53"])]), /Unsupported advisory range comparator/);
    assert.throws(() => advisorySafe("1.0.0", [{ id: "RUSTSEC-2026-0008", versions: { patched: ">=1.0.0", unaffected: [] } }]), /Malformed advisory versions/);
});

test("the same immutable ignore policy gates verify and readmit", () => {
    const ignored = auditIgnores({ advisories: { ignore: ["RUSTSEC-2023-0071"] } });
    assert.deepEqual([...ignored], ["RUSTSEC-2023-0071"]);
    assert.throws(() => auditIgnores({ advisories: { ignore: "RUSTSEC-2023-0071" } }), /Malformed audit ignore policy/);
    const manifest = '[dependencies]\nexample = "0.3"\nignored = "1.0"\n';
    const baseline = { exitCode: 1, database: "d".repeat(40), report: { vulnerabilities: { found: true, count: 1, list: [{ advisory: { id: "RUSTSEC-2026-0001" }, package: { name: "example", version: "0.3.1" }, versions: { patched: [">=0.3.2"], unaffected: [] } }] } } };
    const patched = { exitCode: 0, database: baseline.database, report: { vulnerabilities: { found: false, count: 0, list: [] }, warnings: { unsound: [{ advisory: { id: "RUSTSEC-2023-0071", informational: "unsound", withdrawn: null }, package: { name: "ignored", version: "1.0.0" }, versions: { patched: [], unaffected: [] } }] } } };
    assert.equal(admitAuditPair(baseline, patched, manifest, ignored), true);
    assert.throws(() => admitAuditPair(baseline, patched, manifest, new Set()));
});
