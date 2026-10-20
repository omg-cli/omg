import {
    CIWorkflow,
    cloudflareArtifacts,
    isCiRunnerFailure,
    type CiContext,
    type CiParams,
    type CloudflareArtifacts,
    type CiRunnerResult,
} from "@cloudflare/ci";
import type { RunnerOptions } from "@cloudflare/ci/worker";
import type { WorkflowEvent, WorkflowStep } from "cloudflare:workers";
import type { Env } from "./env";
import { parseStart, parseVerificationEvidence, receiptKey, requestKey, source } from "./contract";
import {
    expectedCloudChecks,
    inapplicableCloudChecks,
    planIdentity,
    runSourceFormat,
} from "../runner/plan.mjs";
import { z } from "zod";
import { backupTransferMode } from "./backup-policy";

declare const Response: typeof import("@cloudflare/workers-types/index.ts").Response;

type CheckResult = Pick<CiRunnerResult, "exitCode" | "logs">;

const config = {
    retries: { limit: 0, delay: 1000 },
    timeout: 1_200_000,
    commandTimeoutMs: 1_170_000,
    snapshotRetentionSeconds: 86_400,
};

const reportSchema = z.strictObject({
    name: z.enum([
        "rust-pgp-license-junit.xml",
        "rust-debian-pure-junit.xml",

        "regression-baseline.json",
        "regression-patched.json",
    ]),
    content: z.string().max(20_000_000),
});

async function digest(text: string) {
    return [
        ...new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text))),
    ]
        .map((value) => value.toString(16).padStart(2, "0"))
        .join("");
}

export class CI extends CIWorkflow<CloudflareArtifacts, Env> {
    static override getProvider() {
        return cloudflareArtifacts({ owner: source.namespace, repo: source.repo });
    }

    protected async pipeline(
        event: WorkflowEvent<CiParams<CloudflareArtifacts>>,
        step: WorkflowStep,
        ci: CiContext,
    ): Promise<void> {
        const stored = await this.env.BACKUP_BUCKET.get(requestKey(event.instanceId));

        if (!stored) throw new Error("Trusted GitHub request missing");
        const request = parseStart(await stored.json());

        if (request.sha !== event.payload.sha || request.ref !== event.payload.ref)
            throw new Error("Requested source differs from Workflow source");

        if (!/^sha256:[a-f0-9]{64}$/.test(this.env.CI_IMAGE_DIGEST ?? ""))
            throw new Error("Trusted image digest must be configured before CI admission");
        const planSha256 = await digest(planIdentity);
        const requiredChecks = expectedCloudChecks(request.ref);

        if (
            request.verification &&
            (!/^[a-f0-9]{40}$/.test(this.env.CI_VERIFIER_REVISION ?? "") ||
                request.verification.verifierRevision !== this.env.CI_VERIFIER_REVISION)
        )
            throw new Error("Requested verifier differs from trusted deployed revision");

        const verificationEnv: Record<string, string> = request.verification
            ? { OMG_VERIFICATION: JSON.stringify(request) }
            : {};

        let regression: ReturnType<typeof parseVerificationEvidence> | null = null;

        const records: {
            name: string;
            exitCode: number;
            stdoutKey: string;
            stderrKey: string;
            stdoutSha256: string;
            stderrSha256: string;
            reports: { name: string; key: string; sha256: string }[];
        }[] = [];

        const save = async (name: string, result: CheckResult) => {
            const prefix = `logs/${event.instanceId}/${name}`;
            // Streams are single-use; retries must capture reusable bytes before entering the step.
            const stdout = await new Response(result.logs.stdout).text();
            const stderr = await new Response(result.logs.stderr).text();

            const evidence = await step.do(
                `preserve-${name}`,
                { retries: { limit: 2, delay: 1000 }, timeout: "1 minute" },
                async () => {
                    await this.env.BACKUP_BUCKET.put(`${prefix}.stdout`, stdout);
                    await this.env.BACKUP_BUCKET.put(`${prefix}.stderr`, stderr);
                    const reports: { name: string; key: string; sha256: string }[] = [];
                    let verification: ReturnType<typeof parseVerificationEvidence> | null = null;

                    for (const line of stdout.split("\n")) {
                        if (line.startsWith("OMG_VERIFICATION=")) {
                            if (name !== "regression-red-green" || verification)
                                throw new Error("Unexpected or duplicate regression evidence");
                            verification = parseVerificationEvidence(
                                request,
                                z.json().parse(JSON.parse(line.slice("OMG_VERIFICATION=".length))),
                            );
                        }

                        if (!line.startsWith("OMG_REPORT=")) continue;
                        const report = reportSchema.parse(
                            JSON.parse(line.slice("OMG_REPORT=".length)),
                        );

                        if (reports.some((previous) => previous.name === report.name))
                            throw new Error("Duplicate CI report identity");
                        const key = `reports/${event.instanceId}/${report.name}`;
                        await this.env.BACKUP_BUCKET.put(key, report.content);
                        reports.push({
                            name: report.name,
                            key,
                            sha256: await digest(report.content),
                        });
                    }

                    if (name === "regression-red-green") {
                        if (
                            !verification ||
                            reports.find((report) => report.name === "regression-baseline.json")
                                ?.sha256 !== verification.baseline.reportSha256 ||
                            reports.find((report) => report.name === "regression-patched.json")
                                ?.sha256 !== verification.patched.reportSha256
                        )
                            throw new Error(
                                "Regression reports are missing or differ from verified evidence",
                            );
                    }

                    return {
                        stdoutSha256: await digest(stdout),
                        stderrSha256: await digest(stderr),
                        reports,
                        verification,
                    };
                },
            );

            records.push({
                name,
                exitCode: result.exitCode,
                stdoutKey: `${prefix}.stdout`,
                stderrKey: `${prefix}.stderr`,
                ...evidence,
            });

            if (name === "regression-red-green") regression = evidence.verification;
        };

        try {
            const deps = await ci.runner({
                name: "frozen-dependencies",
                command: "node /opt/omg-ci/run.mjs install",
                config,
                env: {
                    OMG_CI_IMAGE: this.env.CI_IMAGE_DIGEST,
                    OMG_RUN_ID: request.runId,
                    OMG_RUN_ATTEMPT: request.attempt,
                    OMG_CI_PLAN: planSha256,
                    OMG_CI_BACKUP_MODE: backupTransferMode(this.env),
                },
                cache: {
                    inputs: [
                        "Cargo.toml",
                        "Cargo.lock",
                        "rust-toolchain.toml",
                        ".cargo/**",
                        "vendor/**",
                        "package.json",
                        "bun.lock",
                        "bunfig.toml",
                        ".npmrc",
                        "patches/**",
                        "services/ci-inspector/package.json",
                        "services/ci-inspector/bun.lock",
                        "services/ci-inspector/bunfig.toml",
                        "services/ci-inspector/.npmrc",
                        "services/ci-inspector/patches/**",
                        "services/cloud-ci/package.json",
                        "services/cloud-ci/bun.lock",
                        "services/cloud-ci/bunfig.toml",
                        "services/cloud-ci/.npmrc",
                        "services/cloud-ci/patches/**",
                        "services/ci-coder/package.json",
                        "services/ci-coder/bun.lock",
                        "services/ci-coder/bunfig.toml",
                        "services/ci-coder/.npmrc",
                        "services/ci-coder/patches/**",
                    ],
                },
            });

            if (deps.exitCode !== 0) throw new Error("Dependency runner returned a nonzero exit");
            await save("frozen-dependencies", deps);

            const formatted: CheckResult = await runSourceFormat(deps, config, {
                OMG_EXPECTED_SHA: request.sha,
                OMG_RUN_ID: request.runId,
                OMG_RUN_ATTEMPT: request.attempt,
                OMG_CI_LEAF_STEP: "source-format",
                ...verificationEnv,
            });

            await save("source-format", formatted);

            if (request.verification) {
                const result: CheckResult = await deps.runner({
                    name: "regression-red-green",
                    command: "node /opt/omg-ci/run.mjs regression-red-green",
                    config,
                    env: {
                        OMG_EXPECTED_SHA: request.sha,
                        OMG_RUN_ID: request.runId,
                        OMG_RUN_ATTEMPT: request.attempt,
                        ...verificationEnv,
                    },
                });

                if (result.exitCode !== 0)
                    throw new Error("Regression runner returned a nonzero exit");
                await save("regression-red-green", result);
            }

            const pending = requiredChecks.slice(2);

            for (let index = 0; index < pending.length; index += 2) {
                await Promise.all(
                    pending.slice(index, index + 2).map(async (name) => {
                        const env: NonNullable<RunnerOptions["env"]> = {
                            OMG_EXPECTED_SHA: request.sha,
                            OMG_RUN_ID: request.runId,
                            OMG_RUN_ATTEMPT: request.attempt,
                            OMG_CI_LEAF_STEP: name,
                            ...verificationEnv,
                        };

                        env.OMG_RUN_ID = request.runId;
                        env.OMG_RUN_ATTEMPT = request.attempt;

                        const result: CheckResult = await deps.runner({
                            name,
                            command: `node /opt/omg-ci/run.mjs ${name}`,
                            config,
                            env,
                        });

                        if (result.exitCode !== 0)
                            throw new Error(`${name} returned a nonzero exit`);
                        await save(name, result);
                    }),
                );
            }

            let verificationReceipt = null;

            if (request.verification) {
                const verified = parseVerificationEvidence(request, regression);
                const portableChecks = [];

                for (const name of requiredChecks) {
                    const record = records.find((entry) => entry.name === name);

                    if (!record || record.exitCode !== 0)
                        throw new Error("Required patched check is missing");
                    portableChecks.push({
                        name,
                        exitCode: 0,
                        reportSha256: await digest(JSON.stringify(record)),
                    });
                }

                verificationReceipt = {
                    repository: verified.repository,
                    branch: verified.branch,
                    baseSha: verified.baseSha,
                    proposalSha256: verified.proposalSha256,
                    verifierRevision: verified.verifierRevision,
                    runId: verified.runId,
                    runAttempt: verified.runAttempt,
                    baseline: verified.baseline,
                    patched: verified.patched,
                    portableChecks,
                    protectedPathsUnchanged: verified.protectedPathsUnchanged,
                };
            }

            await step.do(
                "publish-receipt",
                { retries: { limit: 2, delay: 1000 }, timeout: "1 minute" },
                async () => {
                    await this.env.BACKUP_BUCKET.put(
                        receiptKey(request),
                        JSON.stringify({
                            version: 1,
                            engine: "@cloudflare/ci@0.2.0",
                            id: event.instanceId,
                            ...request,
                            conclusion: "success",
                            verificationReceipt,
                            verificationReports:
                                records.find((record) => record.name === "regression-red-green")
                                    ?.reports ?? [],
                            checks: records
                                .filter((record) => record.name !== "regression-red-green")
                                .toSorted(
                                    (left, right) =>
                                        requiredChecks.indexOf(left.name) -
                                        requiredChecks.indexOf(right.name),
                                ),
                            requiredChecks,
                            inapplicableChecks: inapplicableCloudChecks(request.ref),
                            nativeAcceptance: false,
                            imageDigest: this.env.CI_IMAGE_DIGEST,
                            planSha256,
                            completedAt: new Date().toISOString(),
                        }),
                        { httpMetadata: { contentType: "application/json" } },
                    );
                },
            );
        } catch (error) {
            const failure = isCiRunnerFailure(error)
                ? error.output
                : error instanceof Error
                  ? error.message
                  : "Unknown CI failure";

            await step.do(
                "preserve-failure",
                { retries: { limit: 2, delay: 1000 }, timeout: "1 minute" },
                async () => {
                    await this.env.BACKUP_BUCKET.put(
                        `logs/${event.instanceId}/failure.txt`,
                        failure,
                    );
                    await this.env.BACKUP_BUCKET.put(
                        receiptKey(request),
                        JSON.stringify({
                            version: 1,
                            id: event.instanceId,
                            ...request,
                            conclusion: "failure",
                            requiredChecks,
                            inapplicableChecks: inapplicableCloudChecks(request.ref),
                            checks: records,
                            imageDigest: this.env.CI_IMAGE_DIGEST,
                            planSha256,
                            failureKey: `logs/${event.instanceId}/failure.txt`,
                        }),
                    );
                },
            );
            throw error;
        }
    }
}
