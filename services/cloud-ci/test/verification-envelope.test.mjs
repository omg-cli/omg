import { expect, test } from "bun:test";
import { encodeVerificationEnvironment, decodeVerificationEnvironment } from "../runner/verification-envelope.mjs";
import { spawnSync } from "node:child_process";

test("large audit snapshots survive bounded individual environment strings and a real Node child", () => {
    const request = { testAudit: { source: "α".repeat(520000) } };
    const env = encodeVerificationEnvironment(request);
    expect(Object.values(env).every((value) => Buffer.byteLength(value) <= 16000)).toBe(true);
    expect(decodeVerificationEnvironment(env)).toEqual(request);
    const child = spawnSync("node", ["--input-type=module", "-e", `import {decodeVerificationEnvironment} from ${JSON.stringify(new URL("../runner/verification-envelope.mjs", import.meta.url).href)};console.log(JSON.stringify(decodeVerificationEnvironment(process.env)));`],
        { env: { ...process.env, ...env }, encoding: "utf8", timeout: 10000, maxBuffer: 2 * 1024 * 1024, windowsHide: true });
    expect(child.status, child.stderr).toBe(0);
    expect(JSON.parse(child.stdout)).toEqual(request);
    expect(encodeVerificationEnvironment({ verification: { value: "small" } })).toEqual({ OMG_VERIFICATION: '{"verification":{"value":"small"}}' });
});

test("incomplete, ambiguous and oversized verification envelopes fail closed", () => {
    const env = encodeVerificationEnvironment({ testAudit: { source: "x".repeat(150000) } });
    for (const change of [
        { OMG_VERIFICATION_PARTS: "89" }, { OMG_VERIFICATION_0: "corrupt?" }, { OMG_VERIFICATION_0: undefined },
        { OMG_VERIFICATION: "{}" }, { OMG_VERIFICATION_88: "e30=" },
    ]) expect(() => decodeVerificationEnvironment({ ...env, ...change })).toThrow();
    expect(() => encodeVerificationEnvironment({ testAudit: { source: "x".repeat(1024 * 1024) } })).toThrow();
    expect(() => encodeVerificationEnvironment({ verification: { source: "x".repeat(65536) } })).toThrow();
    for (const encoded of ["/w==", "e30", Buffer.from("{}").toString("base64")])
        expect(() => decodeVerificationEnvironment({ OMG_VERIFICATION_PARTS: "1", OMG_VERIFICATION_0: encoded })).toThrow();
    const encoded = Buffer.alloc(1024 * 1024 + 1, 32).toString("base64").match(/.{1,16000}/g);
    expect(() => decodeVerificationEnvironment({ OMG_VERIFICATION_PARTS: String(encoded.length),
        ...Object.fromEntries(encoded.map((part, index) => [`OMG_VERIFICATION_${index}`, part])) })).toThrow();
});
