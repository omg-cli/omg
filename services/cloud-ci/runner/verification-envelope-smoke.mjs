import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { encodeVerificationEnvironment } from "./verification-envelope.mjs";

const request = { testAudit: { source: "x".repeat(1_048_000) } };
const env = encodeVerificationEnvironment(request);
const environmentBytes = Object.entries({ ...process.env, ...env }).reduce((size, [key, value]) => size + Buffer.byteLength(`${key}=${value}\0`), 0);
const limits = spawnSync("getconf", ["ARG_MAX"], { encoding: "utf8", timeout: 10000 });
assert.equal(limits.status, 0, limits.stderr);
assert.ok(Number(limits.stdout.trim()) > environmentBytes + 65536, "Audit environment must retain process argument reserve");
assert.ok(Object.values(env).every((value) => Buffer.byteLength(value) <= 16000));
const decoder = new URL("./verification-envelope.mjs", import.meta.url).href;
const program = `import {decodeVerificationEnvironment} from ${JSON.stringify(decoder)};process.stdout.write(String(Buffer.byteLength(JSON.stringify(decodeVerificationEnvironment(process.env)))));`;
const child = spawnSync(process.execPath, ["--input-type=module", "-e", program], {
    env: { ...process.env, ...env }, encoding: "utf8", timeout: 10000,
});
assert.equal(child.status, 0, child.error?.message ?? child.stderr);
assert.equal(Number(child.stdout), Buffer.byteLength(JSON.stringify(request)));
console.log(`Trusted audit execve verified with ${env.OMG_VERIFICATION_PARTS} chunks and ${environmentBytes} environment bytes`);
