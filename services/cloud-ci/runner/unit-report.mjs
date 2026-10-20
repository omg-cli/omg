export function assertUnitExecution(document) {
  const summary = document.testsuites?.$;
  const cases = namedNodes(document, "testcase");
  const skipped = cases.filter((item) => Object.hasOwn(item, "skipped")).length;
  const reportedSkipped = Number(summary?.skipped ?? skipped);

  if (
    !summary ||
    !Number.isSafeInteger(Number(summary.tests)) ||
    Number(summary.tests) < 1 ||
    Number(summary.tests) !== cases.length ||
    !Number.isSafeInteger(reportedSkipped) ||
    reportedSkipped < 0 ||
    reportedSkipped !== skipped ||
    cases.length - skipped < 1 ||
    Number(summary.failures) !== 0 ||
    Number(summary.errors ?? "0") !== 0 ||
    namedNodes(document, "error").length > 0 ||
    namedNodes(document, "failure").length > 0
  )
    throw new Error("Portable unit report did not prove successful execution");

  return summary;
}

function namedNodes(node, name) {
  if (Array.isArray(node)) return node.flatMap((item) => namedNodes(item, name));

  if (node === null) return [];
  const prototype = Object.getPrototypeOf(node);

  if (prototype !== null && prototype !== Object.prototype) return [];

  return Object.entries(node).flatMap(([key, value]) =>
    key === name ? (Array.isArray(value) ? value : [value]) : namedNodes(value, name),
  );
}
