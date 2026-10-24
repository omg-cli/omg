import {test} from 'bun:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {expectedCloudChecks,expectedCloudReports,planIdentity} from '../../services/cloud-ci/runner/plan.mjs';
import {CloudCiEngineFailure} from '../../scripts/cloud-ci-evidence.mjs';
import {admitFormattingRun,admitPortableTestReceipt,admitSourceFormatting,reviewTarget,runReviewFlow} from '../../scripts/ai-review-flow.mjs';
import {runTestAuditPage} from '../../scripts/test-audit-flow.mjs';
const sha='a'.repeat(40);
const request={repository:'omg-cli/omg',sha,ref:'refs/heads/main',runId:'123',attempt:'1'};
const id=`cl-123-1-${sha}`;
const imageDigest=`sha256:${'b'.repeat(64)}`;
const planSha256=createHash('sha256').update(planIdentity).digest('hex');
const requiredChecks=expectedCloudChecks(request.ref);
const h='c'.repeat(64);
const format={name:'source-format',exitCode:0,stdoutKey:`logs/${id}/source-format.stdout`,stderrKey:`logs/${id}/source-format.stderr`,stdoutSha256:h,stderrSha256:h,reports:[]};
const portable={name:'rust-portable-tests',exitCode:0,reports:expectedCloudReports('rust-portable-tests').map(name=>({name,key:`reports/${id}/${name}`,sha256:'d'.repeat(64)}))};
const receipt=(o={})=>({version:1,engine:'@cloudflare/ci@0.2.0',id,...request,conclusion:'failure',requiredChecks,inapplicableChecks:[],checks:[],imageDigest,planSha256,failureKey:`logs/${id}/failure.txt`,...o});
const engineReceipt=(o={})=>receipt({failureCategory:'workflow-internal-error',...o});
const notEngine=m=>e=>e instanceof Error&&!(e instanceof CloudCiEngineFailure)&&e.message===m;
test('engine classification stays behind every existing formatting guard',()=>{
assert.throws(()=>admitSourceFormatting(engineReceipt(),request,imageDigest),CloudCiEngineFailure);
assert.throws(()=>admitSourceFormatting(engineReceipt({id:`cl-123-1-${'e'.repeat(40)}`}),request,imageDigest),notEngine('Formatting evidence identity mismatch.'));
assert.throws(()=>admitSourceFormatting(engineReceipt({requiredChecks:requiredChecks.slice(1)}),request,imageDigest),notEngine('Source format evidence inventory is invalid.'));
assert.throws(()=>admitSourceFormatting(engineReceipt({failureCategory:undefined}),request,imageDigest),notEngine('Source format did not pass with complete evidence.'));
assert.throws(()=>admitSourceFormatting(engineReceipt({conclusion:'success'}),request,imageDigest),notEngine('Source format did not pass with complete evidence.'));
assert.throws(()=>admitSourceFormatting(engineReceipt({verification:{}}),request,imageDigest),notEngine('Formatting evidence identity mismatch.'));
});
test('missing portable evidence classifies only after formatting is admitted',()=>{
const formattingOnly=engineReceipt({checks:[format]});
assert.deepEqual(admitSourceFormatting(formattingOnly,request,imageDigest),format);
assert.throws(()=>admitPortableTestReceipt(formattingOnly,request,imageDigest),CloudCiEngineFailure);
const usable=engineReceipt({checks:[format,portable]});
assert.equal(admitPortableTestReceipt(usable,request,imageDigest).name,'rust-pgp-license-junit.xml');
assert.throws(()=>admitPortableTestReceipt(receipt({checks:[format]}),request,imageDigest),notEngine('Portable test check is missing or duplicated.'));
assert.throws(()=>admitPortableTestReceipt(engineReceipt({checks:[format,portable,portable]}),request,imageDigest),notEngine('Source format evidence inventory is invalid.'));
});
test('test audit page rethrows only the genuine engine class',async()=>{
const collected={sourceRange:{kind:'test-audit',sha,inventoryDigest:'f'.repeat(64),cursor:0,nextCursor:null,totalPaths:1,pagePaths:1},rows:[{id:'value::checks',status:'selected',request:{sha},task:{path:'src/value.rs',testName:'value::checks'}}]};
let audited=0;
const audit=async()=>{audited++;return null;};
await assert.rejects(()=>runTestAuditPage({collected,sha,branch:'main',formatting:{status:'passed'},publishRequested:false,io:{portableTest:async()=>{throw new CloudCiEngineFailure('workflow-internal-error');},audit}}),CloudCiEngineFailure);
assert.equal(audited,0);
const lookalike=new Error('lookalike engine failure');lookalike.name='CloudCiEngineFailure';
const held=await runTestAuditPage({collected,sha,branch:'main',formatting:{status:'passed'},publishRequested:false,io:{portableTest:async()=>{throw lookalike;},audit}});
assert.equal(held.testAuditOutcomes[0].status,'held');
assert.equal(held.testAuditOutcomes[0].reason,'lookalike engine failure');
assert.equal(audited,0);
});
test('formatting run admission rejects the engine class before blocked evidence',async()=>{
const run=fetchReceipt=>admitFormattingRun({sha,branch:'main',upstream:undefined,runId:'123',attempt:'1',imageDigest,priorImageDigest:undefined,fetchReceipt,startRun:async()=>{},verifyLogs:async()=>{}});
await assert.rejects(()=>run(async()=>engineReceipt()),CloudCiEngineFailure);
await assert.rejects(()=>run(async()=>receipt()),notEngine('Source format did not pass with complete evidence.'));
});
test('review coordinator propagates the engine class before audit or coder work',async()=>{
const target=reviewTarget('workflow_dispatch',{repository:{full_name:'omg-cli/omg'},inputs:{branch:'main',scope:'test-audit',publish:'false'}});
let audited=0,portable=0,reviewed=0;
await assert.rejects(()=>runReviewFlow({target:{...target,sha},io:{head:async()=>sha,collect:async()=>({baseSha:sha,sourceRange:{kind:'test-audit',sha,inventoryDigest:'f'.repeat(64),cursor:0,totalPaths:1,pagePaths:1,nextCursor:null},entries:[{path:'src/value.rs'}],rows:[{id:'value::checks',status:'selected',request:{sha},task:{path:'src/value.rs',testName:'value::checks'}}],unreviewedPaths:[]}),format:async()=>{throw new CloudCiEngineFailure('workflow-internal-error');},portableTest:async()=>{portable++;},audit:async()=>{audited++;return null;},review:async()=>{reviewed++;return null;}}}),CloudCiEngineFailure);
assert.equal(audited,0);assert.equal(portable,0);assert.equal(reviewed,0);
});

test('review coordinator requests portable evidence only for test audits',async()=>{
for(const kind of ['test-audit','audit']){
const stop=new Error('stop after observing format purpose');
let observed;
await assert.rejects(()=>runReviewFlow({target:{branch:'main',sha,range:{kind},publish:false},io:{
head:async()=>sha,
collect:async()=>({baseSha:sha,sourceRange:{kind},entries:[{path:'src/value.rs'}],unreviewedPaths:[]}),
format:async(...args)=>{observed=args;throw stop;},
}}),error=>error===stop);
assert.deepEqual(observed,[sha,'main',undefined,kind==='test-audit']);
}
});
