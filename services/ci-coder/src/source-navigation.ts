import { z } from "zod";
import type { CodingRequest } from "./request";
import {designatedRegressionPath} from "../../ci-inspector/src/review-contract";
import {verificationSchema} from "../../cloud-ci/src/verification-schema";

const locations = (content: string, needle: string) =>
    content
        .split("\n")
        .flatMap((line, index) => (line.includes(needle) ? [index + 1] : []));

export function testAuditContext(request: CodingRequest) {
    const task = request.testAuditTask;
    if (!task) return {};
    const file = request.source.sourceFiles.find(
        (file) => file.path === task.path,
    );
    if (!file) throw new Error("Selected test source missing");
    const name = task.testName.replace(/^.*::/, ""),
        count = file.content.split("\n").length;
    return {
        testAuditTask: z.json().parse(task),
        testWindows: locations(file.content, `fn ${name}(`)
            .slice(0, 20)
            .map((line) => {
                const start = Math.max(1, line - 10);
                return {
                    path: file.path,
                    start,
                    lines: Math.min(80, count - start + 1),
                };
            }),
    };
}

export function repairContext(request: CodingRequest) {
    if(request.testAuditTask||request.dependencyTask||request.diagnosisTask)return {};
    const contract={
        ...(request.rustContext?{rustContext:request.rustContext}:{}),
        ...(request.source.sourceFiles.some(file=>file.path.endsWith(".rs"))?{regressionContract:{
            path:designatedRegressionPath(request.sha,0,true),
            expectedTestName:verificationSchema.shape.regression.shape.testName.toJSONSchema(),
            instruction:"Submit this exact new integration-test path and one matching named case. Use the supplied Cargo library/public exports. The server assigns the published filename after admission; do not guess it.",
        }}:{}),
    };
    if(request.hypothesis?.kind!=="candidates"||request.candidateIndex===undefined)
        return contract;
    const selected=request.hypothesis.candidates[request.candidateIndex];
    if(!selected)throw new Error("Selected repair candidate missing");
    return {
        ...contract,
        repairWindows:selected.evidence.map(item=>{
            const file=request.source.sourceFiles.find(file=>file.path===item.path);
            if(!file)throw new Error("Repair evidence source missing");
            const start=Math.max(1,item.lineStart-10,item.lineEnd-79);
            return {path:item.path,start,lines:Math.min(80,file.content.split("\n").length-start+1)};
        }),
    };
}

const searchInput = z.strictObject({
    path: z.string().min(1).max(300),
    needle: z
        .string()
        .min(2)
        .max(200)
        .refine((value) => !/[\r\n]/.test(value)),
});

export function createSourceSearch(
    enter: (context: {
        sessionID: string;
        signal: AbortSignal;
    }) => Promise<CodingRequest>,
) {
    return {
        input: searchInput,
        description:
            "Find literal text in one supplied immutable source file. Returns at most twenty line numbers, not source-read evidence. Read matched ranges with read_source before citing or proposing a change.",
        async execute(
            raw: z.infer<typeof searchInput>,
            context: { sessionID: string; signal: AbortSignal },
        ) {
            const request = await enter(context),
                input = searchInput.parse(raw);
            const file = request.source.sourceFiles.find(
                (file) => file.path === input.path,
            );
            if (!file)
                throw new Error("Search is outside the supplied snapshot");
            const matches = locations(file.content, input.needle);
            return {
                content: JSON.stringify({
                    path: file.path,
                    lines: file.content.split("\n").length,
                    totalMatches: matches.length,
                    matches: matches.slice(0, 20),
                }),
            };
        },
    };
}
