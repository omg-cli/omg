import { z } from "zod";
import type { CodingRequest } from "./request";
import type { CodingState } from "./tools";
import { parseRuntimeIdentity } from "./runtime";

const version = z
    .string()
    .regex(/^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/)
    .max(40);
const name = z.string().regex(/^[a-z][a-z0-9_-]{0,63}$/);

export const dependencyTaskSchema = z
    .strictObject({
        targets: z
            .array(
                z.strictObject({
                    name,
                    version,
                    availableVersions: z.array(version).min(1).max(5),
                    advisories: z
                        .array(z.string().regex(/^RUSTSEC-[0-9]{4}-[0-9]{4}$/))
                        .min(1)
                        .max(10),
                }),
            )
            .min(1)
            .max(6),
    })
    .refine(
        (task) =>
            new Set(task.targets.map((target) => target.name)).size ===
            task.targets.length,
        "Duplicate dependency targets",
    );

export const dependencyPlanSchema = z.strictObject({
    summary: z.string().min(1).max(2000),
    updates: z
        .array(z.strictObject({ name, from: version, to: version }))
        .min(1)
        .max(6),
});
export type DependencyPlan = z.infer<typeof dependencyPlanSchema>;

export function dependencyLockRange(
    lock: string,
    target: { name: string; version: string },
) {
    const lines = lock.split("\n");
    for (let index = 0; index < lines.length - 2; index++) {
        if (
            lines[index] === "[[package]]" &&
            lines[index + 1] === `name = "${target.name}"` &&
            lines[index + 2] === `version = "${target.version}"`
        )
            return { start: index + 1, end: index + 3 };
    }
    throw new Error("Dependency target differs from exact Cargo.lock source");
}

export function validateDependencyPlan(
    task: z.infer<typeof dependencyTaskSchema>,
    raw: unknown,
): DependencyPlan {
    const plan = dependencyPlanSchema.parse(raw);
    if (
        plan.updates.length !== task.targets.length ||
        new Set(plan.updates.map((update) => update.name)).size !==
            plan.updates.length
    )
        throw new Error(
            "Plan must update each reported dependency exactly once",
        );
    for (const update of plan.updates) {
        const target = task.targets.find(
            (target) => target.name === update.name,
        );
        const before = update.from.split(".").map(Number),
            after = update.to.split(".").map(Number);
        const firstDifference = after.findIndex(
            (part, index) => part !== before[index],
        );
        if (
            !target ||
            target.version !== update.from ||
            !target.availableVersions.includes(update.to) ||
            firstDifference < 0 ||
            after[firstDifference] <= before[firstDifference] ||
            after[0] !== before[0] ||
            (before[0] === 0 && after[1] !== before[1])
        )
            throw new Error(
                "Dependency version must be a supplied stable compatible upgrade",
            );
    }
    return plan;
}

export function admitDependencyResult(
    raw: unknown,
    request: {
        repository: string;
        sha: string;
        branch: string;
        runId: string;
        attempt: string;
        dependencyTask?: z.infer<typeof dependencyTaskSchema>;
        source: { sourceFiles: { path: string; content: string }[] };
    },
    id: string,
    policy: {
        bundleSha256: string;
        imageDigest: string;
        verifierRevision: string;
    },
) {
    const state = z
        .object({
            id: z.literal(id),
            repository: z.literal(request.repository),
            sha: z.literal(request.sha),
            branch: z.literal(request.branch),
            runId: z.literal(request.runId),
            attempt: z.literal(request.attempt),
            status: z.literal("done"),
            initialOperation: z.object({
                operationId: z.literal(id),
                status: z.literal("done"),
            }),
            runtime: z.unknown(),
            skillsDelivery: z.object({
                bundleSha256: z.literal(policy.bundleSha256),
                sessionId: z.string().regex(/^ses_/),
            }),
            result: z.object({
                calls: z.number().int().positive(),
                sessionId: z.string(),
                skillBundleSha256: z.literal(policy.bundleSha256),
                reads: z.array(
                    z.object({
                        path: z.string(),
                        start: z.number().int().positive(),
                        end: z.number().int().positive(),
                    }),
                ),
                dependencyPlan: dependencyPlanSchema,
            }),
        })
        .parse(raw);
    const runtime = parseRuntimeIdentity(JSON.stringify(state.runtime));
    if (
        runtime.bundleSha256 !== policy.bundleSha256 ||
        runtime.imageDigest !== policy.imageDigest ||
        runtime.verifierRevision !== policy.verifierRevision ||
        state.skillsDelivery.sessionId !== state.result.sessionId
    )
        throw new Error("Dependency runtime or skill provenance mismatch");
    const lock = request.source.sourceFiles.find(
        (file) => file.path === "Cargo.lock",
    );
    if (
        !request.dependencyTask ||
        !lock ||
        !state.result.reads.some((read) => read.path === "Cargo.toml")
    )
        throw new Error("Dependency task or manifest read missing");
    for (const target of request.dependencyTask.targets) {
        const range = dependencyLockRange(lock.content, target);
        if (
            !state.result.reads.some(
                (read) =>
                    read.path === "Cargo.lock" &&
                    read.start <= range.start &&
                    read.end >= range.end,
            )
        )
            throw new Error("Dependency lockfile read missing");
    }
    return validateDependencyPlan(
        request.dependencyTask,
        state.result.dependencyPlan,
    );
}

export function createDependencyTool(
    enter: (context: {
        sessionID: string;
        signal: AbortSignal;
    }) => Promise<CodingRequest>,
    update: (
        change: (state: CodingState) => CodingState,
    ) => Promise<CodingState>,
) {
    return {
        input: dependencyPlanSchema,
        description:
            "Select one supplied stable compatible upgrade per failed dependency after reading lockfile evidence and manifest. Exports a plan only; separate trusted hosted verification and publication are required.",
        async execute(
            input: z.infer<typeof dependencyPlanSchema>,
            context: { sessionID: string; signal: AbortSignal },
        ) {
            const request = await enter(context);
            if (!request.dependencyTask)
                throw new Error("No dependency repair task");
            const plan = validateDependencyPlan(request.dependencyTask, input);
            const lock = request.source.sourceFiles.find(
                (file) => file.path === "Cargo.lock",
            );
            if (!lock) throw new Error("Dependency lockfile source missing");
            await update((state) => {
                if (
                    !state.reads.some((read) => read.path === "Cargo.toml") ||
                    request.dependencyTask?.targets.some((target) => {
                        const range = dependencyLockRange(lock.content, target);
                        return !state.reads.some(
                            (read) =>
                                read.path === "Cargo.lock" &&
                                read.start <= range.start &&
                                read.end >= range.end,
                        );
                    })
                )
                    throw new Error(
                        "Read the manifest and each exact locked dependency before proposing updates",
                    );
                return { ...state, dependencyPlan: plan };
            });
            return {
                content: JSON.stringify({
                    plan,
                    verified: false,
                    instruction:
                        "Stop this turn. The trusted hosted verifier must apply this plan, prove audit before/after results and publish separately. Do not call ordinary source verification or claim success.",
                }),
            };
        },
    };
}
