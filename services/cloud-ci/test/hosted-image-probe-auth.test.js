import { describe, expect, test } from "bun:test";
import { authenticate, credentialRequest, loginArgs, parseCredentials } from "./hosted-image-probe.mjs";

const HOST = "registry.cloudflare.com";
const SECRET = "registry-password-value";
const TOKEN = "test-api-token";

function response(payload, status = 200) {
    return { ok: status >= 200 && status < 300, status, json: async () => payload };
}

describe("credential request scope", () => {
    test("asks for a 15 minute pull-only credential on the exact registry host", () => {
        const { url, init } = credentialRequest("account-id", TOKEN, HOST);
        expect(url).toBe("https://api.cloudflare.com/client/v4/accounts/account-id/containers/registries/registry.cloudflare.com/credentials");
        expect(url).not.toContain(TOKEN);
        expect(init.method).toBe("POST");
        expect(init.redirect).toBe("error");
        expect(init.headers.authorization).toBe(`Bearer ${TOKEN}`);
        expect(init.headers["content-type"]).toBe("application/json");
        expect(JSON.parse(init.body)).toEqual({ permissions: ["pull"], expiration_minutes: 15 });
    });

    test("rejects a response for a different registry host", () => {
        expect(() => parseCredentials({ success: true, result: { username: "ci", password: SECRET, registry_host: "evil.example" } }, HOST)).toThrow("registry host mismatch");
    });

    test("rejects a response without a password", () => {
        expect(() => parseCredentials({ success: true, result: { username: "ci", registry_host: HOST } }, HOST)).toThrow("password missing");
    });
});

describe("login ordering and redaction", () => {
    test("fetches first, then logs in with the password only on stdin and an owned Docker config", async () => {
        const calls = [];
        const dockerConfig = "/tmp/owned-docker-config";
        const spawn = (command, args, options) => {
            calls.push({ command, args, options });
            return { status: 0 };
        };
        const fetchImpl = async (url, init) => {
            calls.push({ url, init });
            return response({ success: true, result: { username: "ci", password: SECRET, registry_host: HOST } });
        };
        const previous = process.env.DOCKER_HOST;
        process.env.DOCKER_HOST = "tcp://docker-daemon:2375";
        try {
            await authenticate("account-id", TOKEN, HOST, dockerConfig, { fetchImpl, spawn });
        } finally {
            if (previous === undefined) delete process.env.DOCKER_HOST;
            else process.env.DOCKER_HOST = previous;
        }
        expect(calls).toHaveLength(2);
        expect(calls[0].url).toContain("/containers/registries/registry.cloudflare.com/credentials");
        expect(calls[1].command).toBe("docker");
        expect(calls[1].args).toEqual(["login", HOST, "--username", "ci", "--password-stdin"]);
        expect(calls[1].args.join(" ")).not.toContain(SECRET);
        expect(calls[1].options.input).toBe(SECRET);
        expect(calls[1].options.env.DOCKER_CONFIG).toBe(dockerConfig);
        expect(calls[1].options.env.DOCKER_HOST).toBe("tcp://docker-daemon:2375");
    });

    test("propagates HTTP failure without reading or printing the secret body", async () => {
        let bodyRead = false;
        const fetchImpl = async () => ({ ok: false, status: 401, json: async () => { bodyRead = true; return { result: { password: SECRET } }; } });
        const spawn = () => { throw new Error("login must not run"); };
        const error = await authenticate("account-id", TOKEN, HOST, "/tmp/owned", { fetchImpl, spawn }).then(() => null, (value) => value);
        expect(error?.message).toBe("Registry credential request failed with HTTP 401");
        expect(error?.message).not.toContain(SECRET);
        expect(bodyRead).toBe(false);
    });

    test("propagates login failure", async () => {
        const fetchImpl = async () => response({ success: true, result: { username: "ci", password: SECRET, registry_host: HOST } });
        const spawn = () => ({ status: 1 });
        const error = await authenticate("account-id", TOKEN, HOST, "/tmp/owned", { fetchImpl, spawn }).then(() => null, (value) => value);
        expect(error?.message).toBe("Registry login failed with exit 1");
    });
});

test("login arguments never carry the password", () => {
    const args = loginArgs(HOST, "ci");
    expect(args).toEqual(["login", HOST, "--username", "ci", "--password-stdin"]);
    expect(args.join(" ")).not.toContain(SECRET);
});

