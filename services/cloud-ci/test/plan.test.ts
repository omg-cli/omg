import { expect, test } from "bun:test";
import {
    rustProfiles,
    cloudCiChecks,
    expectedCloudChecks,
    expectedCloudReports,
    inapplicableCloudChecks,
    planIdentity,
    runServiceCheck,
    runSourceFormat,
} from "../runner/plan.mjs";
test("OMG main has fixed Rust/script checks and exact retained reports", () => {
    expect(expectedCloudChecks("refs/heads/main")).toEqual(cloudCiChecks);
    expect(cloudCiChecks).toContain("ci-inspector-service");
    expect(cloudCiChecks.slice(0, 2)).toEqual(["frozen-dependencies", "source-format"]);
    expect(expectedCloudReports("rust-portable-tests")).toEqual([
        "rust-pgp-license-junit.xml",
        "rust-debian-pure-junit.xml",
    ]);
    expect(expectedCloudReports("regression-red-green")).toEqual([
        "regression-baseline.json",
        "regression-patched.json",
    ]);
    expect(inapplicableCloudChecks("refs/heads/main")).toEqual([]);
    for (const branch of ["prerelease", "other"])
        expect(() => expectedCloudChecks(`refs/heads/${branch}`)).toThrow();
    expect(() => expectedCloudReports("shell arbitrary")).toThrow();
    expect(JSON.parse(planIdentity).verification.mode).toBe("new-rust-regression-only");
});
test("format admission preserves actual output and blocks dependent work on failure", async () => {
    const result = { exitCode: 0, logs: { stdout: "formatted", stderr: "" } };
    expect(await runSourceFormat({ runner: async () => result }, {}, {})).toBe(result);
    await expect(
        runSourceFormat({ runner: async () => ({ exitCode: 1 }) }, {}, {}),
    ).rejects.toThrow("Source formatting failed");
});
test("only present trusted services run check/build/test in order", async () => {
    const calls: string[][] = [];
    await runServiceCheck("cloud-ci-service", {
        exists: () => true,
        run: async (command: string, args: string[]) => {
            calls.push([command, ...args]);
        },
    });
    expect(calls.map((args) => args.at(-1))).toEqual(["check", "build", "test"]);
    await expect(
        runServiceCheck("source-script-injected", { exists: () => true }),
    ).rejects.toThrow();
    await expect(runServiceCheck("ci-coder-service", { exists: () => false })).rejects.toThrow();
});

test("each cloud Rust profile has the existing native surface policy for both binaries", async () => {
    const manifest = await Bun.file(new URL("../../../tests/contracts/manifest.json", import.meta.url)).json() as {
        surface_digests: { platform: string; features: string[]; binary: string }[];
    };
    for (const profile of rustProfiles) {
        const selected = manifest.surface_digests.filter((row) =>
            row.platform === profile.platform && row.features.toSorted().join(",") === profile.features?.split(",").sort().join(","));
        expect(selected.map((row) => row.binary).sort()).toEqual(["omg", "omgd"]);
    }
});
