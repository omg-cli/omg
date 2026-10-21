import { expect, test } from "bun:test";
import { readFile } from "node:fs/promises";

test("retained unit bytes round trip through the actual Workers R2 binding", async () => {
  const source = await readFile(
    new URL("../src/unit-report-retention.ts", import.meta.url),
    "utf8",
  );

  const implementation = new Bun.Transpiler({ loader: "ts" }).transformSync(source);

  const worker =
    implementation +
    `
    export default {async fetch(request,env) {
      const bytes=new Uint8Array([60,255,0,38,62]);
      const sandbox={
        async listFiles(){return {success:true,files:[{absolutePath:'/tmp/omg-ci-unit-evidence/report.xml',type:'file',size:bytes.length}]};},
        async readReport(){return new ReadableStream({start(c){c.enqueue(bytes);c.close();}});}
      };
      const id='cl-123-1-'+ 'a'.repeat(40);
      const status=await retainUnitReport(id,sandbox,env.BUCKET);
      const object=await env.BUCKET.get('reports/'+id+'/portable-units.xml');
      return Response.json({status,bytes:object?Array.from(new Uint8Array(await object.arrayBuffer())):null,contentType:object?.httpMetadata.contentType});
    }};`;

  const program = `
    import {createRequire} from 'node:module';
    const require=createRequire(${JSON.stringify(new URL("../node_modules/wrangler/package.json", import.meta.url).href)});
    const {Miniflare,convertV4MiniflareOptions}=require('miniflare');
    const mf=new Miniflare(convertV4MiniflareOptions({modules:true,compatibilityDate:'2026-10-20',r2Buckets:['BUCKET'],script:${JSON.stringify(worker)}}));
    try{const response=await mf.dispatchFetch('https://fixture.invalid/');console.log(JSON.stringify({status:response.status,body:await response.json()}));}finally{await mf.dispose();}
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
  expect(JSON.parse(output)).toEqual({
    status: 200,
    body: { status: "saved", bytes: [60, 255, 0, 38, 62], contentType: "application/xml" },
  });
});
