import { expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { gitBlobSha } from "../../../scripts/ai-review-candidate.mjs";
import { parseCodingRequest } from "../src/request";
import { buildTestAuditProposal } from "../src/test-audit";

const root = fileURLToPath(new URL("..", import.meta.url));
const WRANGLER_MANIFEST = fileURLToPath(new URL("../node_modules/wrangler/package.json", import.meta.url));

function wranglerCli() {
  const { bin } = JSON.parse(readFileSync(WRANGLER_MANIFEST, "utf8"));
  const entry = typeof bin === "string" ? bin : (bin?.wrangler ?? bin?.wrangler2);
  if (!entry) throw new Error("Installed Wrangler package has no CLI bin entry");
  const wrapper = resolve(dirname(WRANGLER_MANIFEST), entry);
  if (!existsSync(wrapper)) throw new Error("Installed Wrangler CLI wrapper is missing");
  const referenced = /([\w./-]*wrangler-dist\/cli\.js)/.exec(readFileSync(wrapper, "utf8"))?.[1];
  if (!referenced) throw new Error("Installed Wrangler wrapper does not name the direct CLI entry");
  const direct = resolve(dirname(wrapper), referenced);
  if (!existsSync(direct)) throw new Error("Installed Wrangler direct CLI entry is missing");
  return direct;
}

async function buildCallerBundle(contents, deadline) {
  const directory = mkdtempSync(join(tmpdir(), "omg-caller-bundle-"));
  const owned = resolve(directory);
  if (dirname(owned) !== resolve(tmpdir()) || !basename(owned).startsWith("omg-caller-bundle-"))
    throw new Error("Temporary bundle directory escaped the system temporary directory");
  try {
    writeFileSync(join(directory, "caller.ts"), contents);
    writeFileSync(
      join(directory, "wrangler.json"),
      JSON.stringify({
        name: "omg-ci-coder-caller-fixture",
        main: "caller.ts",
        compatibility_date: "2026-10-20",
        compatibility_flags: ["nodejs_compat"],
      }),
    );
    const outdir = join(directory, "out");
    const result = spawnSync(
      "node",
      [wranglerCli(), "deploy", "--dry-run", "--outdir", outdir, "--config", join(directory, "wrangler.json")],
      {
        cwd: directory,
        encoding: "utf8",
        timeout: Math.max(1, deadline - Date.now()),
        killSignal: "SIGKILL",
        env: { ...process.env, CI: "1", WRANGLER_SEND_METRICS: "false" },
      },
    );
    const logs = [result.stdout, result.stderr, result.error?.message].filter(Boolean);
    if (result.status !== 0) return { success: false, logs, script: "" };
    const emitted = readdirSync(outdir, { recursive: true });
    const scripts = emitted.filter((name) => /^[A-Za-z0-9_-]+\.js$/.test(name));
    const permitted = new Set([...scripts, "README.md"]);
    if (scripts.length === 1) permitted.add(`${scripts[0]}.map`);
    const unsupported = emitted.filter((name) => !permitted.has(name));
    if (unsupported.length) throw new Error(`Wrangler dry-run emitted unsupported runtime modules: ${unsupported.join(", ")}`);
    if (scripts.length !== 1) throw new Error(`Wrangler dry-run wrote ${scripts.length} scripts: ${scripts.join(", ")}`);
    return { success: true, logs, script: readFileSync(join(outdir, scripts[0]), "utf8") };
  } finally {
    rmSync(owned, { recursive: true, force: true });
  }
}
const TEST_SOURCE = '#[test]\nfn checks_value() {\n    let value = 1;\n    assert!(value > 0);\n}\n';
const FAULT_SOURCE = "pub const VALUE: u32 = 1;\n";
const SHA = "a".repeat(40);
const TEST_BLOB = gitBlobSha(TEST_SOURCE);
const FAULT_BLOB = gitBlobSha(FAULT_SOURCE);
const PROPOSE = {
  purpose: "existing-test-strengthening",
  assertion: { line: 4, source: "    assert_eq!(value, 1);" },
  fault: { path: "src/value.rs", oldQuote: "VALUE: u32 = 1", replacement: "VALUE: u32 = 2" },
};
const REQUEST = {
  repository: "omg-cli/omg", sha: SHA, branch: "main", runId: "42", attempt: "1",
  source: {
    repository: "omg-cli/omg", sha: SHA, branch: "main", changedPaths: [], diff: "",
    auditPaths: ["tests/value.rs", "src/value.rs"], ciFailures: [],
    sourceFiles: [
      { path: "tests/value.rs", blobSha: TEST_BLOB, content: TEST_SOURCE },
      { path: "src/value.rs", blobSha: FAULT_BLOB, content: FAULT_SOURCE },
    ],
  },
  testAuditTask: { path: "tests/value.rs", testName: "checks_value", originalBlobSha: TEST_BLOB },
};
const PARSED_REQUEST = parseCodingRequest(REQUEST);
const BUILT = buildTestAuditProposal(PARSED_REQUEST, PROPOSE);
const DIGEST = BUILT.proposalSha256;
const EXPECTED_ID = `cl-${REQUEST.runId}-${REQUEST.attempt}-${REQUEST.sha}-ta-${DIGEST.slice(0, 16)}`;
const EXPECTED_BODY = {
  repository: REQUEST.repository,
  sha: REQUEST.sha,
  ref: `refs/heads/${REQUEST.branch}`,
  runId: REQUEST.runId,
  attempt: REQUEST.attempt,
  testAudit: { proposal: BUILT.proposal, verifierRevision: "d".repeat(40) },
};

const callerEntry = `import { Coder as BaseCoder } from ${JSON.stringify(`${root}/src/harness.ts`)};
import handler from ${JSON.stringify(`${root}/src/index.ts`)};
const PROPOSE = ${JSON.stringify(PROPOSE)};
const sse = (text) => new Response(stream([{ choices: [{ index: 0, delta: { role: "assistant", content: text } }] }, { choices: [{ index: 0, delta: {}, finish_reason: "stop" }], usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 } }]), { headers: { "content-type": "text/event-stream" } });
const stream = (events) => [...events.map((event) => JSON.stringify(event)), "[DONE]"].map((data) => "data: " + data + "\\n\\n").join("");
const toolCall = (name, args) => new Response(stream([{ choices: [{ index: 0, delta: { role: "assistant", tool_calls: [{ index: 0, id: "call_1", type: "function", function: { name, arguments: JSON.stringify(args) } }] } }] }, { choices: [{ index: 0, delta: {}, finish_reason: "tool_calls" }], usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 } }]), { headers: { "content-type": "text/event-stream" } });
const textOf = (content) => typeof content === "string" ? content : Array.isArray(content) ? content.map((part) => typeof part === "object" && part !== null && typeof part.text === "string" ? part.text : "").join("") : "";
const messages = (input) => Array.isArray(input.messages) ? input.messages : [];
const lastUser = (input) => { const all = messages(input); for (let i = all.length - 1; i >= 0; i--) { const m = all[i]; if (typeof m === "object" && m !== null && m.role === "user") return textOf(m.content); } return ""; };
const toolResults = (input) => messages(input).filter((m) => typeof m === "object" && m !== null && m.role === "tool").map((m) => textOf(m.content));
const ai = { aiGatewayLogId: null, async run(model, input) {
  if (input.stream !== true || !Array.isArray(input.tools)) {
    if (input.stream === true) return sse("title");
    return Response.json({ choices: [{ index: 0, finish_reason: "stop", message: { role: "assistant", content: "title" } }], usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 } });
  }
  const prompt = lastUser(input);
  const results = toolResults(input);
  if (prompt.startsWith("Trusted controller handoff")) {
    const digest = (prompt.match(/[a-f0-9]{64}/) || [""])[0];
    if (results.some((text) => text.includes('"status":"pending"'))) return sse("verification requested");
    return toolCall("execute", { code: 'return await tools.verify_patch({proposalSha256:"' + digest + '"})' });
  }
  const last = results.at(-1);
  if (last === undefined) return toolCall("execute", { code: 'return await tools.read_source({path:"tests/value.rs",start:1,lines:80})' });
  if (last.includes('"path":"tests/value.rs"')) return toolCall("execute", { code: 'return await tools.read_source({path:"src/value.rs",start:1,lines:80})' });
  if (last.includes('"path":"src/value.rs"')) return toolCall("execute", { code: "return await tools.propose_test_strengthening(" + JSON.stringify(PROPOSE) + ")" });
  return sse("proposal admitted");
} };
export class Coder extends BaseCoder {
  constructor(ctx, env) { super(ctx, { ...env, AI: ai, MODEL_PACER: { getByName() { return { async admit() { return { granted: true }; } }; } } }); }
  async debugState() { return (await this.ctx.storage.get("coding-result")) ?? null; }
  async debugPending() { return await this.harness.pending(); }
}
export default {
  async fetch(request, env) {
    const path = new URL(request.url).pathname;
    if (path === "/__ci_calls") return env.CI_SERVICE.fetch("https://ci/__calls");
    if (path.startsWith("/__state/")) {
      const coder = env.CODER.getByName(path.slice(9));
      return Response.json({ state: await coder.debugState(), pending: await coder.debugPending() });
    }
    return handler.fetch(request, env);
  },
};`;

const ciEntry = `const calls = [];
const EXPECTED_ID = ${JSON.stringify(EXPECTED_ID)};
export default { async fetch(request) {
  const url = new URL(request.url);
  if (url.pathname === "/__calls") return Response.json(calls);
  if (url.pathname === "/runs" && request.method === "POST") {
    const body = await request.text();
    calls.push({ method: "POST", path: "/runs", body: JSON.parse(body) });
    return Response.json({ id: EXPECTED_ID, sha: ${JSON.stringify(SHA)} });
  }
  const match = /^\\/runs\\/(.+)$/.exec(url.pathname);
  if (match && match[1] === EXPECTED_ID) return Response.json({ id: EXPECTED_ID, sha: ${JSON.stringify(SHA)}, status: "running" });
  return new Response("not found", { status: 404 });
} };`;

async function start() {
  const deadline = Date.now() + 25000;
  const built = await buildCallerBundle(callerEntry, deadline);
  expect(built.success, built.logs.join("\n")).toBe(true);
  const program = `import {createRequire} from 'node:module';
const require=createRequire(${JSON.stringify(new URL("../node_modules/wrangler/package.json", import.meta.url).href)});
const {Miniflare,convertV4MiniflareOptions}=require('miniflare');
const mf=new Miniflare(convertV4MiniflareOptions({workers:[
 {name:'caller',modules:true,compatibilityDate:'2026-10-20',compatibilityFlags:['nodejs_compat'],script:${JSON.stringify(built.script)},
  serviceBindings:{CI_SERVICE:'ci'},durableObjects:{CODER:{className:'Coder',useSQLite:true}},
  bindings:{CODER_API_TOKEN:${JSON.stringify("coder-token".repeat(8))},CI_API_TOKEN:${JSON.stringify("ci-token".repeat(8))},CI_IMAGE_DIGEST:${JSON.stringify(`sha256:${"b".repeat(64)}`)},CI_VERIFIER_REVISION:${JSON.stringify("d".repeat(40))}}},
 {name:'ci',modules:true,compatibilityDate:'2026-10-20',script:${JSON.stringify(ciEntry)}}
]}));
try{
 const request=${JSON.stringify(REQUEST)};
 const auth={Authorization:'Bearer '+${JSON.stringify("coder-token".repeat(8))}};
 const created=await mf.dispatchFetch('https://fixture.invalid/operations',{method:'POST',headers:{...auth,'content-type':'application/json'},body:JSON.stringify(request)});
 if(created.status!==202)throw new Error('admission failed: '+created.status+' '+await created.text());
 const id=(await created.json()).id;
 const read=async(path)=>mf.dispatchFetch('https://fixture.invalid'+path,{headers:auth});
 const debug=async()=>await (await read('/__state/'+id)).json();
 let debugged;
 for(let i=0;i<100;i++){
   debugged=await debug();
   if(debugged.state?.testAudit?.proposalSha256 && !debugged.pending.some((operation)=>operation.operationId===id))break;
   await new Promise(r=>setTimeout(r,50));
 }
 const afterFirst=(await (await read('/__ci_calls')).json()).filter(c=>c.method==='POST');
 const admitted=Boolean(debugged.state?.testAudit?.proposalSha256);
 if(!admitted)throw new Error('setup: proposal was not admitted through the real tool');
 const firstStatus=await (await read('/operations/'+id)).json();
 const handoffStatus=firstStatus.status;
 for(let i=0;i<100;i++){
   debugged=await debug();
   if(debugged.state?.verificationJob)break;
   await new Promise(r=>setTimeout(r,50));
 }
 const state=debugged.state;
 const afterHandoff=(await (await read('/__ci_calls')).json()).filter(c=>c.method==='POST');
 const again=await (await read('/operations/'+id)).json();
 const afterRepeat=(await (await read('/__ci_calls')).json()).filter(c=>c.method==='POST');
 console.log(JSON.stringify({admitted,afterFirst:afterFirst.length,afterHandoff:afterHandoff.length,afterRepeat:afterRepeat.length,requests:afterHandoff.map(c=>c.body),handoffStatus,again:again.status,state:{job:state&&state.verificationJob,verification:state&&state.verification,audit:state&&state.testAudit&&state.testAudit.proposalSha256,sessionId:state&&state.sessionId,skill:state&&state.skillBundleSha256},status:firstStatus}));
}finally{await mf.dispose();}`;
  const child = Bun.spawn(["node", "--input-type=module", "-"], {
    stdin: new TextEncoder().encode(program), stdout: "pipe", stderr: "pipe", timeout: Math.max(1, deadline - Date.now()), killSignal: "SIGKILL",
  });
  const [code, stdout, stderr] = await Promise.all([
    child.exited, new Response(child.stdout).text(), new Response(child.stderr).text(),
  ]);
  expect(code, stderr).toBe(0);
  return JSON.parse(stdout);
}

test("an admitted existing-test audit reaches the real verify_patch through the real Coder status path", async () => {
  const result = await start();
  expect(result.admitted, JSON.stringify(result)).toBe(true);
  expect(result.afterFirst, JSON.stringify(result)).toBe(0);
  expect(result.state.job, JSON.stringify(result)).not.toBeNull();
  expect(result.afterHandoff, JSON.stringify(result)).toBe(1);
  expect(result.requests).toEqual([EXPECTED_BODY]);
  expect(result.handoffStatus, JSON.stringify(result)).toBe("running");
  expect(result.state.job.status).toBe("pending");
  expect(result.state.verification).toBeUndefined();
  expect(result.afterRepeat, JSON.stringify(result)).toBe(1);
  expect(result.again).toBe("running");
  expect(result.state.sessionId).toBe(result.state.job.sessionId);
  expect(result.state.skill.length).toBe(64);
}, 30000);

test("read-only diagnosis cannot enter the test-audit handoff", () => {
  expect(() => parseCodingRequest({ ...REQUEST, diagnosisTask: { question: "why" } })).toThrow(/no coding task/);
});
