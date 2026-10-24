import { expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import { assertUnitExecution } from "../runner/unit-report.mjs";

for (const partialSkips of [false, true]) {
  test(`actual Bun JUnit with ${partialSkips ? "partial skips" : "only executed cases"} survives XML parsing`, () => {
    const moduleUrl = new URL("../runner/unit-report.mjs", import.meta.url).href;
    const runnerPackageUrl = new URL("../runner/package.json", import.meta.url).href;

    const child = spawnSync(process.execPath, [
      "--eval",
      `
        import assert from "node:assert/strict";
        import { spawnSync } from "node:child_process";
        import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
        import { tmpdir } from "node:os";
        import path from "node:path";
        import { createRequire } from "node:module";
        import { parseStringPromise } from "xml2js";
        import { assertUnitExecution } from ${JSON.stringify(moduleUrl)};
        assert.equal(Bun.version, "1.4.4");
        const require = createRequire(import.meta.url);
        const declaredPin = JSON.parse(readFileSync(new URL(${JSON.stringify(runnerPackageUrl)}), "utf8")).dependencies.xml2js;
        assert.equal(declaredPin, "0.5.0");
        assert.equal(require("xml2js/package.json").version, declaredPin);
        const directory = mkdtempSync(path.join(tmpdir(), "codeloud-junit-emitter-"));
        try {
          const fixture = path.join(directory, "actual.test.mjs");
          const report = path.join(directory, "actual.xml");
          const source = ${JSON.stringify(
            'import test from "node:test"; import assert from "node:assert/strict"; import {describe,test as bunTest} from "bun:test"; test("actual executed case",()=>assert.equal(6,6));' +
              (partialSkips
                ? 'test("actual skipped case",{skip:true},()=>assert.fail("must stay skipped")); describe.skipIf(true)("nested skipped suite",()=>{bunTest("nested first",()=>assert.fail("must stay skipped"));bunTest("nested second",()=>assert.fail("must stay skipped"));});'
                : ""),
          )};
          const emit = (source) => {
            writeFileSync(fixture, source);
            const child = spawnSync(process.execPath, ["test", fixture, "--reporter=junit", "--reporter-outfile=" + report], {
              env: { ...process.env, GITHUB_SHA: "a".repeat(40), GITHUB_RUN_ID: "123", GITHUB_SERVER_URL: "https://github.com", GITHUB_REPOSITORY: "omg-cli/omg" },
            });
            return { status: child.status, stderr: child.stderr, raw: readFileSync(report, "utf8") };
          };
          const emitted = emit(source);
          assert.equal(emitted.status, 0, emitted.stderr.toString());
          const raw = emitted.raw;
          const commitProperty = '<property name="commit" value="' + "a".repeat(40) + '" />';
          assert.ok(raw.includes(commitProperty));
          assert.ok(raw.indexOf(commitProperty) < raw.indexOf("<testcase "));
          const document = await parseStringPromise(raw);
          assert.equal(Object.getPrototypeOf(document.testsuites), null);
          const summary = assertUnitExecution(document);
          assert.equal(summary.tests, ${JSON.stringify(partialSkips ? "4" : "1")});
          assert.equal(summary.skipped, ${JSON.stringify(partialSkips ? "3" : "0")});
          assert.equal(summary.failures, "0");
          assert.equal(Object.hasOwn(summary, "errors"), false);
          const setupFailure = raw.replace(/(<testcase [^>]*?) *\\/>/, "$1><error>fixture setup failure</error></testcase>");
          assert.notEqual(setupFailure, raw);
          for (const malformed of [raw.replace('tests="${partialSkips ? "4" : "1"}"', 'tests="99"'), raw.replace('failures="0"', 'failures="1"'), raw.replace('skipped="${partialSkips ? "3" : "0"}"', 'skipped="99"'), raw.split("\\n").filter(line => !line.includes('name="actual executed case"')).join("\\n"), setupFailure]) {
            const parsed = await parseStringPromise(malformed);
            assert.throws(() => assertUnitExecution(parsed));
          }
          const failed = emit(source.replace("assert.equal(6,6)", "assert.equal(6,7)"));
          assert.equal(failed.status, 1);
          const failedDocument = await parseStringPromise(failed.raw);
          assert.throws(() => assertUnitExecution(failedDocument));
          const falseGreen = await parseStringPromise(failed.raw.replace('failures="1"', 'failures="0"'));
          assert.throws(() => assertUnitExecution(falseGreen));
          const allSkipped = emit(source.replace('test("actual executed case",', 'test("actual executed case",{skip:true},'));
          assert.equal(allSkipped.status, 0);
          const skippedDocument = await parseStringPromise(allSkipped.raw);
          assert.throws(() => assertUnitExecution(skippedDocument));
          console.log("actual emitted unit cases admitted");
        } finally { rmSync(directory, { recursive: true, force: true }); }
      `,
    ]);

    expect(child.status, new TextDecoder().decode(child.stderr)).toBe(0);
    expect(new TextDecoder().decode(child.stdout)).toContain("actual emitted unit cases admitted");
  });
}

test("zero tests, failed tests and nested setup errors cannot pass admission", () => {
  for (const document of [
    { testsuites: { $: { tests: "0", failures: "0" } } },
    { testsuites: { $: { tests: "1", failures: "1" } } },
    {
      testsuites: {
        $: { tests: "1", failures: "0" },
        testsuite: [{ testcase: [{ error: [{ _: "setup error" }] }] }],
      },
    },
  ])
    expect(() => assertUnitExecution(document)).toThrow();
});

test("an all-skipped suite cannot count as successful portable execution", () => {
  expect(() =>
    assertUnitExecution({
      testsuites: {
        $: { tests: "2", failures: "0", skipped: "2" },
        testsuite: [
          {
            testcase: [
              { $: { name: "first" }, skipped: [{}] },
              { $: { name: "second" }, skipped: [{}] },
            ],
          },
        ],
      },
    }),
  ).toThrow("Portable unit report did not prove successful execution");
});
