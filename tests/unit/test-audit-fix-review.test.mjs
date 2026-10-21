import { test, expect } from "bun:test";
import { testAuditProofFixture } from "./fixtures/test-audit-proof.mjs";
import { readmitTestAuditProof, testAuditPublicationBodies } from "../../scripts/test-audit-publication.mjs";
import { reviewAiFix, gitBlobSha } from "../../scripts/ai-fix-review.mjs";
import { patchReviewDigest } from "../../services/ci-inspector/src/patch-review-contract.ts";

async function fixture(options) {
    const proof = testAuditProofFixture(options);
    const admitted = await readmitTestAuditProof(proof);
    const base = proof.request.sha, head = "b".repeat(40), tree = "c".repeat(40);
    const publisher = { login: "omg-ci-publisher[bot]", id: 345568822 };
    const body = testAuditPublicationBodies(admitted).pullRequest;
    const pull = { number: 7, state: "open", draft: false, user: publisher, body,
        base: { ref: "main", sha: base, repo: { full_name: "omg-cli/omg" } },
        head: { ref: `ai-fix/${admitted.proposal.finding.key.slice(0,16)}-${base.slice(0,12)}`, sha: head, repo: { full_name: "omg-cli/omg" } } };
    const policy = { ...proof.policy, controllerRevision: "f".repeat(40), reviewControllerRevision: base };
    const report = { repository: "omg-cli/omg", branch: "main", sha: base,
        controllerRevision: policy.controllerRevision, publishRequested: true, publications: [],
        testAudits: [{ request: proof.request, receipt: proof.receipt, id: proof.id, coderOperationId: "private-coder-operation" }] };
    const files = new Map([[proof.proposal.test.path,proof.original], [proof.proposal.fault.path,proof.production]]);
    const baseTree = { truncated: false, tree: [...files].map(([path,content]) => ({ path,mode:"100644",type:"blob",sha:gitBlobSha(content) })) };
    const headTree = structuredClone(baseTree);
    headTree.tree.find((file) => file.path===proof.proposal.test.path).sha=gitBlobSha(proof.proposal.test.newContent);
    const checks=["CI Success","Instrumented coverage tests","Generate Coverage Report","Orchestration tests, types and dry builds","QEMU behavioral verification / QEMU matrix result"].map(name=>({ name,head_sha:head,status:"completed",conclusion:"success",app:{id:15368,slug:"github-actions"} }));
    const state={posts:[],saved:[],inspected:[],verdict:"approved",pullReads:0,mutateFresh:false};
    const github={async request(method,route,data){
        if(method==="POST"){state.posts.push({route,data});return{id:1,commit_id:data.commit_id,state:"APPROVED",user:{id:41898282,login:"github-actions[bot]"}};}
        if(route.includes("/check-runs?"))return{check_runs:checks};
        if(route.endsWith("/git/ref/heads/main"))return{object:{sha:base}};
        if(route.endsWith("/pulls/7")){state.pullReads++;return structuredClone(state.mutateFresh&&state.pullReads>1?{...pull,head:{...pull.head,sha:"9".repeat(40)}}:pull);}
        if(route.includes("/reviews?"))return[];
        if(route.endsWith("/actions/runs/42/attempts/1"))return{id:42,run_attempt:1,status:"completed",conclusion:"success",event:"workflow_dispatch",repository:{full_name:"omg-cli/omg"},head_branch:"main",head_sha:base,path:".github/workflows/ai-review.yml"};
        if(route.includes("/actions/runs/42/attempts/1/jobs?"))return{jobs:[{id:4201,name:"review",workflow_name:"AI source review",run_id:42,run_attempt:1,run_url:"https://api.github.com/repos/omg-cli/omg/actions/runs/42",head_branch:"main",head_sha:base,status:"completed",conclusion:"success"}]};
        if(route.endsWith(`/git/commits/${base}`))return{sha:base,tree:{sha:"0".repeat(40)}};
        if(route.endsWith(`/git/commits/${head}`))return{sha:head,tree:{sha:tree},parents:[{sha:base}]};
        if(route.includes(`/git/trees/${"0".repeat(40)}`))return baseTree;
        if(route.includes(`/git/trees/${tree}`))return headTree;
        if(route.includes("/git/blobs/")){const content=[...files.values()].find(value=>route.endsWith(gitBlobSha(value)));return{encoding:"base64",content:Buffer.from(content).toString("base64")};}
        throw new Error("Unexpected audit approval route");
    }};
    const services={ciJson:async route=>route.startsWith("/review-records/")?report:proof.receipt,
        ciRaw:async route=>{const parts=route.split("/");return proof.load(`${parts[3]}/${proof.id}/${parts[4]}`);},
        admitQemu:async()=>{},saveReview:async record=>state.saved.push(record),
        inspectPatch:async input=>{state.inspected.push(input);return{purpose:input.purpose,inputSha256:patchReviewDigest(input),baseSha:input.baseSha,headSha:input.headSha,headTreeSha:input.headTreeSha,proposalSha256:input.proposalSha256,model:"@cf/deepseek-ai/deepseek-v4.1-flash-1017",readCompletePatch:true,codeExecutions:1,result:{verdict:state.verdict,reason:state.reason??"Additional assertion checks the intended behavior without changing old assertions.",findings:[]}};}};
    return{...proof,github,services,number:7,expectedHead:head,publisher,policy,approve:true,state,report,pull,headTree};
}

test("existing-test approval independently admits actual four-state bytes and the complete test-only tree",async()=>{
    const input=await fixture();
    expect((await reviewAiFix(input)).action).toBe("approved");
    expect(input.state.inspected[0].purpose).toBe("test-strengthening-approval");
    expect(input.state.inspected[0].patch).toEqual([{path:input.proposal.test.path,before:input.original,after:input.proposal.test.newContent}]);
    expect(input.state.inspected[0].audit.fault.newContent).toBe(input.proposal.fault.newContent);
    expect(input.state.saved).toHaveLength(1);
    expect(input.state.posts).toHaveLength(1);
    expect(input.state.posts[0].data.commit_id).toBe(input.expectedHead);
    expect(JSON.stringify(input.state.posts)).not.toContain(input.proposal.fault.newContent);
});

for(const [name,mutate]of[
    ["corrupted raw fault report",input=>input.objects.set(input.receipt.testAuditReports[1].key,"corrupted")],
    ["controlled fault added to published tree",input=>{input.headTree.tree.find(file=>file.path===input.proposal.fault.path).sha=gitBlobSha(input.proposal.fault.newContent);}],
    ["changed original controller",input=>{input.report.controllerRevision="9".repeat(40);}],
    ["unreviewed current head",input=>{input.state.mutateFresh=true;}],
])test(`existing-test approval rejects ${name}`,async()=>{
    const input=await fixture();mutate(input);
    await expect(reviewAiFix(input)).rejects.toThrow();
    expect(input.state.posts).toHaveLength(0);
});

test("insufficient semantic evidence retains the strengthened test for human review without approval",async()=>{
    const input=await fixture();input.state.verdict="insufficient-evidence";
    expect((await reviewAiFix(input)).action).toBe("held");
    expect(input.state.posts).toHaveLength(0);
});

test("a private controlled fault echoed by the semantic reviewer never enters the public approval",async()=>{
    const input=await fixture();input.state.reason=input.proposal.fault.newContent;
    expect((await reviewAiFix(input)).action).toBe("approved");
    expect(JSON.stringify(input.state.posts)).not.toContain(input.proposal.fault.newContent);
    expect(input.state.saved[0].receipt.result.reason).toBe(input.proposal.fault.newContent);
});

test("audit-only approval reads the complete actual 200 KiB test and reviews every before/after byte", async()=>{
    const input=await fixture({paddingBytes:200*1024});
    expect(Buffer.byteLength(input.original)).toBeGreaterThan(200*1024);
    expect((await reviewAiFix(input)).action).toBe("approved");
    expect(input.state.inspected[0].patch[0].before).toBe(input.original);
    expect(input.state.inspected[0].patch[0].after).toBe(input.proposal.test.newContent);
});
