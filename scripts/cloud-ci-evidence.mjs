import { Schema } from "effect";
import { createHash } from "node:crypto";
import {
    expectedCloudChecks,
    expectedCloudReports,
    planIdentity,
} from "../services/cloud-ci/runner/plan.mjs";

const start = Schema.Struct({
    repository: Schema.Literal("omg-cli/omg"),
    sha: Schema.String.check(Schema.isPattern(/^[a-f0-9]{40}$/)),
    ref: Schema.Literal("refs/heads/main"),
    runId: Schema.String.check(Schema.isPattern(/^[1-9][0-9]{0,19}$/)),
    attempt: Schema.String.check(Schema.isPattern(/^[1-9][0-9]{0,5}$/)),
    sourceBaseSha: Schema.optionalKey(Schema.String.check(Schema.isPattern(/^[a-f0-9]{40}$/))),
});

export const parseCloudCiRequest = Schema.decodeUnknownSync(start);

export const cloudCiChecks = expectedCloudChecks("refs/heads/main");
export const cloudCiPlanSha256 = createHash("sha256").update(planIdentity).digest("hex");

export async function verifyCloudCiObjects(receipt, load) {
    const objects = [
        ...receipt.checks.flatMap((check) => [
            { key: check.stdoutKey, sha256: check.stdoutSha256 },
            { key: check.stderrKey, sha256: check.stderrSha256 },
            ...check.reports,
        ]),
        ...(receipt.verificationReports ?? []),
    ];
    for (const object of objects) {
        const response = await load(object.key);
        if (!response.ok || !response.body)
            throw new Error(`Cloudflare CI evidence unavailable: ${object.key}.`);
        const hash = createHash("sha256");
        for await (const chunk of response.body) hash.update(chunk);
        if (hash.digest("hex") !== object.sha256)
            throw new Error(`Cloudflare CI evidence hash mismatch: ${object.key}.`);
    }
}

const check = Schema.Struct({
    name: Schema.String,
    exitCode: Schema.Literal(0),
    stdoutKey: Schema.String.check(Schema.isPattern(/^logs\/.+\.stdout$/)),
    stderrKey: Schema.String.check(Schema.isPattern(/^logs\/.+\.stderr$/)),
    stdoutSha256: Schema.String.check(Schema.isPattern(/^[a-f0-9]{64}$/)),
    stderrSha256: Schema.String.check(Schema.isPattern(/^[a-f0-9]{64}$/)),
    reports: Schema.Array(
        Schema.Struct({
            name: Schema.String,
            key: Schema.String,
            sha256: Schema.String.check(Schema.isPattern(/^[a-f0-9]{64}$/)),
        }),
    ),
});

const proof = Schema.Struct({
    ...start.fields,
    conclusion: Schema.Literal("success"),
    requiredChecks: Schema.Array(Schema.String),
    checks: Schema.Array(check),
    verificationReports: Schema.Array(
        Schema.Struct({
            name: Schema.String,
            key: Schema.String,
            sha256: Schema.String.check(Schema.isPattern(/^[a-f0-9]{64}$/)),
        }),
    ),
});

export function verifyCloudCiReceipt(receipt, expected, policy) {
    const request = parseCloudCiRequest(expected);

    for (const [key, value] of Object.entries(request))
        if (receipt[key] !== value) throw new Error(`Cloudflare CI identity mismatch: ${key}.`);

    if (receipt.conclusion !== "success") throw new Error("Cloudflare CI did not pass.");

    if (
        !Schema.is(
            Schema.Struct({
                imageDigest: Schema.String.check(Schema.isPattern(/^sha256:[a-f0-9]{64}$/)),
            }),
        )(policy) ||
        receipt.imageDigest !== policy.imageDigest
    )
        throw new Error("Cloudflare CI image differs from the trusted controller.");

    if (receipt.planSha256 !== cloudCiPlanSha256)
        throw new Error("Cloudflare CI plan differs from the trusted controller.");

    if (!Schema.is(proof)(receipt)) throw new Error("Cloudflare CI checks lack passing evidence.");

    const required = expectedCloudChecks(request.ref);

    for (const names of [receipt.requiredChecks, receipt.checks.map((entry) => entry.name)])
        if (
            names.length !== required.length ||
            new Set(names).size !== names.length ||
            required.some((name) => !names.includes(name))
        )
            throw new Error("Cloudflare CI checks are missing or duplicated.");

    if (policy.proposalSha256 !== undefined && !/^[a-f0-9]{64}$/.test(policy.proposalSha256))
        throw new Error("Cloudflare CI proposal identity is invalid.");
    const id = `cl-${request.runId}-${request.attempt}-${request.sha}${policy.proposalSha256 ? `-v-${policy.proposalSha256.slice(0, 16)}` : ""}`;

    for (const check of receipt.checks) {
        if (
            check.stdoutKey !== `logs/${id}/${check.name}.stdout` ||
            check.stderrKey !== `logs/${id}/${check.name}.stderr` ||
            new Set(check.reports.map((report) => report.name)).size !== check.reports.length ||
            check.reports.some(
                (report) =>
                    !expectedCloudReports(check.name).includes(report.name) ||
                    report.key !== `reports/${id}/${report.name}`,
            )
        )
            throw new Error("Cloudflare CI object identity mismatch.");

        const requiredReports = expectedCloudReports(check.name);

        if (
            check.reports.length !== requiredReports.length ||
            requiredReports.some((name) => !check.reports.some((report) => report.name === name))
        )
            throw new Error("Cloudflare CI required reports are missing or unexpected.");
    }

    const verificationNames = policy.proposalSha256
        ? ["regression-baseline.json", "regression-patched.json"]
        : [];
    if (
        receipt.verificationReports.length !== verificationNames.length ||
        new Set(receipt.verificationReports.map((report) => report.name)).size !==
            verificationNames.length ||
        receipt.verificationReports.some((report) => {
            const role = report.name === "regression-baseline.json" ? "baseline" : "patched";
            return (
                !verificationNames.includes(report.name) ||
                report.key !== `reports/${id}/${report.name}` ||
                report.sha256 !== receipt.verificationReceipt?.[role]?.reportSha256
            );
        })
    )
        throw new Error(
            "Cloudflare CI verification proof reports are missing or differ from the summary.",
        );

    return receipt;
}
