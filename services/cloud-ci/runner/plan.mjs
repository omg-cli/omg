export const cloudCiChecks = [
    "frozen-dependencies",
    "source-format",
    "rust-portable-tests",
    "script-contracts",
    "cloud-ci-service",
    "ci-coder-service",
    "ci-inspector-service",
];
export function expectedCloudChecks(ref, workload) {
    if (ref !== "refs/heads/main") throw new Error("Unsupported CI branch");
    return [...selectCloudPlan(workload).checks];
}
export function inapplicableCloudChecks(ref, workload) {
    expectedCloudChecks(ref, workload);
    return [];
}
export function expectedCloudReports(name, workload) {
    if (!selectCloudPlan(workload).checks.includes(name) && name !== "regression-red-green")
        throw new Error("Unknown trusted check");
    if (name === "ubuntu-native-readonly") return ["ubuntu-native.json", "ubuntu-daemon.json"];
    if (name === "rust-portable-tests")
        return ["rust-pgp-license-junit.xml", "rust-debian-pure-junit.xml"];
    if (name === "regression-red-green")
        return ["regression-baseline.json", "regression-patched.json"];
    return [];
}
export const toolchain = {
    bun: "1.4.4+38afee6c8",
    node: "v24.22.1",
    rust: "1.95.0",
    nativeCi: "0.2.0",
    sandbox: "0.12.14",
};
export const rustProfiles = [
    { features: "pgp,license", platform: "portable" },
    { features: "debian-pure", platform: "debian-pure" },
];
export const rustTimeouts = { step: 2_400_000, command: 2_370_000, child: 2_340_000 };
export const scriptTimeouts = { step: 2_400_000, command: 2_370_000, child: 2_340_000 };
export const planIdentity = JSON.stringify({
    version: 1,
    repository: "omg-cli/omg",
    cloudCiChecks,
    rustProfiles,
    rustTimeouts,
    scriptTimeouts,
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
    applicability: { main: [...cloudCiChecks] },
});
const ubuntuChecks = ["frozen-dependencies", "source-format", "ubuntu-native-readonly"];
export const knownCloudChecks = [...new Set([...cloudCiChecks, ...ubuntuChecks])];
export const ubuntuPlanIdentity = JSON.stringify({
    version: 1,
    repository: "omg-cli/omg",
    workload: "ubuntu-native-pilot",
    checks: ubuntuChecks,
    distro: "ubuntu",
    versionId: "24.04",
    features: "debian,pgp,license",
    profile: "release",
    toolchain,
    rustTimeouts,
    nativeAcceptance: false,
});
export function selectCloudPlan(workload) {
    if (workload === undefined)
        return { checks: cloudCiChecks, identity: planIdentity, install: "install" };
    if (workload === "ubuntu-native-pilot")
        return { checks: ubuntuChecks, identity: ubuntuPlanIdentity, install: "ubuntu-install" };
    throw new Error("Unsupported trusted CI workload");
}
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
