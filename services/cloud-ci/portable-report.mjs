import { parseStringPromise } from "xml2js";
import { assertUnitExecution } from "./runner/unit-report.mjs";

export async function assertPortableTestMember(xml, suite, testName) {
    const document = await parseStringPromise(xml);
    assertUnitExecution(document);
    const suites = document.testsuites?.testsuite ?? [];
    const matches = suites.filter(item => item.$?.name === suite)
        .flatMap(item => item.testcase ?? [])
        .filter(item => item.$?.classname === suite && item.$?.name === testName);
    if (matches.length !== 1 || Object.hasOwn(matches[0], "skipped"))
        throw new Error("Portable test is not executed exactly once in this recipe");
    return { classname: suite, name: testName };
}
