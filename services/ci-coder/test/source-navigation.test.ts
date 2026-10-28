import assert from "node:assert/strict";
import { test } from "bun:test";
import { Session } from "@opencode/schema/session";
import { createCodingActions, type CodingState } from "../src/tools";
import { createRequiredSkillsPlugin } from "../src/skills";
import { parseCodingRequest } from "../src/request";
import { gitBlobSha } from "../../../scripts/ai-review-candidate.mjs";
import { parseRustCatalog, parseRustExecution } from "../../cloud-ci/runner/rust-evidence.mjs";

async function fixture(deliver = true, repair = false) {
    const content =
        "// fixture line\n".repeat(1700) +
        "#[test]\nfn selected_case() { assert_eq!(value(), 1); }\n" +
        "pub fn value() -> u32 { 1 }\n".repeat(25);
    const sha = "a".repeat(40),
        path = "src/fixture.rs",
        blobSha = gitBlobSha(content);
    const request = parseCodingRequest({
        repository: "omg-cli/omg",
        sha,
        branch: "main",
        runId: "44",
        attempt: "1",
        source: {
            repository: "omg-cli/omg",
            sha,
            branch: "main",
            changedPaths: [],
            auditPaths: [path],
            diff: "",
            sourceFiles: [{ path, blobSha, content }],
            ciFailures: [],
        },
        ...(repair ? {hypothesis:{kind:"candidates",summary:"Supported source hypothesis",candidates:[{
            title:"Wrong source behavior",impact:"The public result is incorrect.",proposedFix:null,
            evidence:[{path,blobSha,lineStart:1702,lineEnd:1703,quote:content.split("\n").slice(1701,1703).join("\n")}],
        }]},candidateIndex:0,rustContext:[{path:"src/lib.rs",content:"pub mod fixture;\n",blobSha:gitBlobSha("pub mod fixture;\n")}]} : {testAuditTask: {
            path,
            target: "lib",
            testName: "module::selected_case",
            originalBlobSha: blobSha,
        }}),
    });
    const skills = await createRequiredSkillsPlugin(),
        sessionID = Session.ID.create();
    if (deliver) skills.contextHook({ sessionID, system: [] });
    let state: CodingState = { calls: 0, reads: [], verifiedDigests: [] };
    const actions = createCodingActions({
        getRequest: async () => request,
        skills,
        update: async (change) => (state = change(state)),
        env: {
            CI_API_TOKEN: "x".repeat(32),
            CI_IMAGE_DIGEST: `sha256:${"b".repeat(64)}`,
            CI_VERIFIER_REVISION: "c".repeat(40),
            CI_SERVICE: {
                fetch: async () => {
                    throw new Error("Navigation must not execute verification");
                },
            },
        },
    });
    return {
        actions,
        request,
        context: { sessionID, signal: new AbortController().signal },
        state: () => state,
    };
}

test("recovered audit context locates the exact selected test without scanning the file", async () => {
    const f = await fixture();
    const context = JSON.parse(
        (await f.actions.read_context.execute({}, f.context)).content,
    );
    assert.deepEqual(context.testAuditTask, f.request.testAuditTask);
    assert.deepEqual(context.testWindows, [
        { path: "src/fixture.rs", start: 1692, lines: 37 },
    ]);
    const files = JSON.parse(
        (await f.actions.list_sources.execute({}, f.context)).content,
    ).files;
    assert.equal(files[0].lines, 1728);
    const read = JSON.parse(
        (await f.actions.read_source.execute(context.testWindows[0], f.context))
            .content,
    );
    assert.ok(read.content.includes("fn selected_case()"));
    assert.equal(f.state().calls, 3);
    assert.equal(f.state().reads.length, 1);
});

test("repair context directs real reads to candidate evidence and keeps API context outside editable source", async () => {
    const f=await fixture(true,true);
    const context=JSON.parse((await f.actions.read_context.execute({},f.context)).content);
    assert.deepEqual(context.repairWindows,[{path:"src/fixture.rs",start:1692,lines:37}]);
    assert.deepEqual(context.rustContext,f.request.rustContext);
    assert.equal(f.state().reads.length,0);
    const read=JSON.parse((await f.actions.read_source.execute(context.repairWindows[0],f.context)).content);
    assert.ok(read.content.includes("fn selected_case()"));
    await assert.rejects(f.actions.read_source.execute({path:"src/lib.rs",start:1,lines:1},f.context),/outside|Unknown/i);
    const evidence=f.request.hypothesis?.kind==="candidates"?f.request.hypothesis.candidates[0]!.evidence:[];
    await assert.rejects(f.actions.propose_fix.execute({kind:"candidates",summary:"Invalid context edit",candidates:[{
        title:"Wrong source behavior",impact:"The result is incorrect.",evidence,
        proposedFix:{edits:[{path:"src/lib.rs",oldText:"pub mod fixture;",newText:"pub mod other;"}],
            regressionTest:{path:`tests/ci-review-${f.request.sha.slice(0,12)}-1.rs`,content:'#[path="../src/fixture.rs"] mod fixture; #[test] fn result() { assert_eq!(fixture::value(), 2); }',expectedTestName:"result"}},
    }]},f.context),/admitted source|source snapshot/i);
    assert.equal(f.state().proposal,undefined);
    assert.equal(f.state().verificationJob,undefined);
});

test("Rust repair context supplies an assertion example accepted by the unchanged proof parser",async()=>{
    const f=await fixture(true,true);
    const context=JSON.parse((await f.actions.read_context.execute({},f.context)).content);
    assert.ok(context.regressionContract.baselineFailure,"Missing baseline assertion requirements");
    const file=context.regressionContract.path,testName="regression";
    const execute=(source:string,message:string)=>parseRustExecution({
        stdout:`running 1 test\ntest regression ... FAILED\ntest result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n`,
        stderr:`thread 'regression' panicked at ${file}:2:1:\n${message}\n`,
        exitCode:101,testName,file,source,catalog:parseRustCatalog("regression: test\n",testName),
    });
    const result=execute(context.regressionContract.baselineFailure.example,"assertion failed: outcome.is_ok()");
    assert.equal(result.failures,1);
    assert.ok("assertionFile" in result && "assertionLine" in result);
    assert.equal(result.assertionFile,file);
    assert.equal(result.assertionLine,2);
    assert.throws(()=>execute('let outcome = operation_under_test();\noutcome.expect("operation must succeed");',"operation must succeed"),/setup or did not reach/);
    assert.throws(()=>execute('let outcome = operation_under_test();\nassert!(outcome.is_ok(), "operation must succeed");',"operation must succeed"),/setup or did not reach/);
});

test("repair navigation covers an entire eighty-line evidence span without exceeding the read bound",async()=>{
    const f=await fixture(true,true);
    if(f.request.hypothesis?.kind!=="candidates")throw new Error("Repair fixture missing");
    const file=f.request.source.sourceFiles[0]!;
    f.request.hypothesis.candidates[0]!.evidence=[{path:file.path,blobSha:file.blobSha,lineStart:1400,lineEnd:1479,
        quote:file.content.split("\n").slice(1399,1479).join("\n")}];
    const context=JSON.parse((await f.actions.read_context.execute({},f.context)).content);
    assert.deepEqual(context.repairWindows,[{path:file.path,start:1400,lines:80}]);
    await f.actions.read_source.execute(context.repairWindows[0],f.context);
    assert.deepEqual(f.state().reads,[{path:file.path,start:1400,end:1479}]);
});

test("ordinary discovery keeps read-only API context even without a selected hypothesis",async()=>{
    const f=await fixture(true,true);
    delete f.request.hypothesis;
    delete f.request.candidateIndex;
    const context=JSON.parse((await f.actions.read_context.execute({},f.context)).content);
    assert.deepEqual(context.rustContext,f.request.rustContext);
    assert.equal(context.repairWindows,undefined);
    assert.equal(f.state().reads.length,0);
});

test("literal source search is skill-gated, bounded and grants no fabricated read evidence", async () => {
    const f = await fixture(false);
    assert.equal(typeof f.actions.find_source, "object");
    await assert.rejects(
        f.actions.find_source.execute(
            { path: "src/fixture.rs", needle: "fn selected_case(" },
            f.context,
        ),
    );
    const valid = await fixture();
    const match = JSON.parse(
        (
            await valid.actions.find_source.execute(
                { path: "src/fixture.rs", needle: "fn selected_case(" },
                valid.context,
            )
        ).content,
    );
    assert.deepEqual(match, {
        path: "src/fixture.rs",
        lines: 1728,
        totalMatches: 1,
        matches: [1702],
    });
    const many = JSON.parse(
        (
            await valid.actions.find_source.execute(
                { path: "src/fixture.rs", needle: "pub fn value()" },
                valid.context,
            )
        ).content,
    );
    assert.equal(many.matches.length, 20);
    assert.equal(many.totalMatches, 25);
    const literal = JSON.parse(
        (
            await valid.actions.find_source.execute(
                { path: "src/fixture.rs", needle: ".*" },
                valid.context,
            )
        ).content,
    );
    assert.deepEqual(literal.matches, []);
    await assert.rejects(
        valid.actions.find_source.execute(
            { path: "../secret", needle: "value" },
            valid.context,
        ),
    );
    for (const needle of ["", "x\ny", "x".repeat(201)])
        await assert.rejects(
            valid.actions.find_source.execute(
                { path: "src/fixture.rs", needle },
                valid.context,
            ),
        );
    assert.equal(valid.state().reads.length, 0);
});
