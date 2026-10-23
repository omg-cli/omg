import { expect, test } from "bun:test";
import { fileURLToPath } from "node:url";

test("retained unit bytes round trip through the actual Workers R2 binding", async () => {
  const built = await Bun.build({
    entrypoints: [fileURLToPath(new URL("../src/unit-report-retention.ts", import.meta.url))],
    target: "browser",
  });
  expect(built.success, built.logs.map(entry=>entry.message).join("\n")).toBe(true);
  const implementation = await built.outputs[0].text();

  const worker =
    implementation +
    `
    export default {async fetch(request,env) {
      const mode=new URL(request.url).pathname.slice(1);
      const bytes=new Uint8Array([60,255,0,38,62]);
      const sandbox={
        async listFiles(path){
          if(path==='/tmp')return {success:true,count:3,files:[
            {absolutePath:'/tmp/omg-ci-unit-evidence',type:'directory',size:0},
            {absolutePath:'/tmp/ci-step.out',type:'file',size:bytes.length},
            {absolutePath:'/tmp/ci-step.err',type:'file',size:bytes.length},
          ]};
          return {success:true,count:1,files:[{absolutePath:'/tmp/omg-ci-unit-evidence/report.xml',type:'file',size:bytes.length}]};
        },
        async readReport(){return new ReadableStream({start(c){c.enqueue(bytes);c.close();}});}
      };
      const id='cl-123-1-'+ 'a'.repeat(40);
      const status=mode==='unit'?await retainUnitReport(id,sandbox,env.BUCKET):await retainRunnerLog(id,'script-contracts',mode,sandbox,env.BUCKET);
      const object=await env.BUCKET.get(mode==='unit'?'reports/'+id+'/portable-units.xml':'diagnostics/runner-logs/'+id+'/script-contracts.'+mode);
      return Response.json({status,bytes:object?Array.from(new Uint8Array(await object.arrayBuffer())):null,contentType:object?.httpMetadata.contentType});
    }};`;

  const program = `
    import {createRequire} from 'node:module';
    const require=createRequire(${JSON.stringify(new URL("../node_modules/wrangler/package.json", import.meta.url).href)});
    const {Miniflare,convertV4MiniflareOptions}=require('miniflare');
    const mf=new Miniflare(convertV4MiniflareOptions({modules:true,compatibilityDate:'2026-10-20',r2Buckets:['BUCKET'],script:${JSON.stringify(worker)}}));
    try{const results=[];for(const mode of ['unit','stdout','stderr']){const response=await mf.dispatchFetch('https://fixture.invalid/'+mode);results.push({mode,status:response.status,body:await response.json()});}console.log(JSON.stringify(results));}finally{await mf.dispose();}
  `;

  const child = Bun.spawn(["node", "--input-type=module", "-"], {
    stdin: new TextEncoder().encode(program),
    stdout: "pipe",
    stderr: "pipe",
  });

  const [code, output, errors] = await Promise.all([
    child.exited,
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
  ]);

  expect(code, errors).toBe(0);
  const results = JSON.parse(output);
  expect(results.map(result=>result.mode)).toEqual(["unit","stdout","stderr"]);
  for (const result of results) {
    expect(result).toEqual({
      mode: result.mode,
      status: 200,
      body: { status: "saved", bytes: [60,255,0,38,62], contentType: result.mode === "unit" ? "application/xml" : "text/plain; charset=utf-8" },
    });
  }
});
