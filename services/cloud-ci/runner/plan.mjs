export const cloudCiChecks = [
    "frozen-dependencies",
    "source-format",
    "rust-portable-tests",
    "script-contracts",
    "cloud-ci-service",
    "ci-coder-service",
    "ci-inspector-service",
];
export function expectedCloudChecks(ref) {
    if (ref !== "refs/heads/main") throw new Error("Unsupported CI branch");
    return [...cloudCiChecks];
}
export function inapplicableCloudChecks(ref) {
    expectedCloudChecks(ref);
    return [];
}
export function expectedCloudReports(name) {
    if (!cloudCiChecks.includes(name) && name !== "regression-red-green")
        throw new Error("Unknown trusted check");
    if (name === "rust-portable-tests")
        return ["rust-pgp-license-junit.xml", "rust-debian-pure-junit.xml"];
    if (name === "regression-red-green")
        return ["regression-baseline.json", "regression-patched.json"];
    return [];
}
export const toolchain = {
    bun: "1.4.2+744846f84",
    node: "v24.21.0",
    rust: "1.95.0",
    nativeCi: "0.2.0",
    sandbox: "0.12.12",
};
export const rustProfiles = [
    { features: "pgp,license", platform: "portable" },
    { features: "debian-pure", platform: "debian-pure" },
];
export const rustTimeouts = { step: 2_400_000, command: 2_370_000, child: 2_340_000 };
export const planIdentity = JSON.stringify({
    version: 1,
    repository: "omg-cli/omg",
    cloudCiChecks,
    rustProfiles,
    rustTimeouts,
    toolchain,
    scriptContracts: {
        partition: "exact-native-ids-v2",
        nativeGate: "Workflow checks",
        nativeCommand: "make ci-workflow-quick",
        nativeAcceptance: false,
    },
    verification: {
        check: "regression-red-green",
        maximumRequestBytes: 65536,
        proposalAppliedToEveryPortableRunner: true,
        requiresTrustedVerifierRevision: true,
        mode: "new-rust-regression-only",
        held: ["existing-test-strengthening-needs-four-states", "dependency-changes-need-receipts"],
    },
    applicability: { main: expectedCloudChecks("refs/heads/main") },
});
export async function runSourceFormat(dependencies, config, env) {
    const result = await dependencies.runner({
        name: "source-format",
        command: "node /opt/omg-ci/run.mjs source-format",
        config,
        env,
    });
    if (result.exitCode !== 0)
        throw new Error("Source formatting failed; dependent checks stopped");
    return result;
}
export async function runServiceCheck(name, dependencies) {
    const directory = {
        "cloud-ci-service": "services/cloud-ci",
        "ci-coder-service": "services/ci-coder",
        "ci-inspector-service": "services/ci-inspector",
    }[name];
    if (!directory || !dependencies.exists(`/workspace/${directory}/package.json`))
        throw new Error("Required trusted service source is absent");
    for (const action of ["check", "build", "test"])
        await dependencies.run("bun", ["run", "--cwd", directory, action]);
}
