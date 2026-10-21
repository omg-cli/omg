const auditLimit = 1024 * 1024;
const normalLimit = 64 * 1024;
const chunkSize = 16000;

export function encodeVerificationEnvironment(request) {
    const text = JSON.stringify(request);
    if (Buffer.byteLength(text) > (request.testAudit ? auditLimit : normalLimit))
        throw new Error("Verification request exceeds its byte budget");
    if (!request.testAudit) return { OMG_VERIFICATION: text };
    const encoded = Buffer.from(text).toString("base64");
    const parts = encoded.match(new RegExp(`.{1,${chunkSize}}`, "g"));
    return { OMG_VERIFICATION_PARTS: String(parts.length),
        ...Object.fromEntries(parts.map((part, index) => [`OMG_VERIFICATION_${index}`, part])) };
}

export function decodeVerificationEnvironment(env) {
    const count = env.OMG_VERIFICATION_PARTS;
    const names = Object.keys(env).filter((key) => /^OMG_VERIFICATION_[0-9]+$/.test(key));
    if (!count) {
        if (names.length) throw new Error("Unexpected verification chunks");
        if (!env.OMG_VERIFICATION) return null;
        if (Buffer.byteLength(env.OMG_VERIFICATION) > normalLimit) throw new Error("Verification payload exceeds 64 KiB");
        return JSON.parse(env.OMG_VERIFICATION);
    }
    if (env.OMG_VERIFICATION || !/^(?:[1-9]|[1-7][0-9]|8[0-8])$/.test(count) || names.length !== Number(count))
        throw new Error("Ambiguous or incomplete audit verification envelope");
    let encoded = "";
    for (let index = 0; index < Number(count); index++) {
        const part = env[`OMG_VERIFICATION_${index}`];
        if (typeof part !== "string" || !part || part.length > chunkSize || !/^[A-Za-z0-9+/=]+$/.test(part))
            throw new Error("Invalid audit verification chunk");
        encoded += part;
    }
    const bytes = Buffer.from(encoded, "base64");
    if (bytes.length > auditLimit || bytes.toString("base64") !== encoded)
        throw new Error("Invalid audit verification encoding or byte budget");
    const request = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
    if (!request.testAudit || request.verification) throw new Error("Chunked verification is reserved for test audits");
    return request;
}
