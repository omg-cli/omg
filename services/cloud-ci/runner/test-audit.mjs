import { createHash } from "node:crypto";

export const testAuditPhases = ["oldIntact", "oldFault", "strongerFault", "strongerIntact"];
export const testAuditReportNames = testAuditPhases.map((phase) => `test-audit-${phase}.json`);
export const testAuditPhasesFor = (proposal) => proposal.purpose === "existing-test-sensitivity" ? testAuditPhases.slice(0, 2) : testAuditPhases;
export const auditHash = (value) => createHash("sha256").update(value).digest("hex");
const blob = (value) => createHash("sha1").update(`blob ${Buffer.byteLength(value)}\0`).update(value).digest("hex");

function rustCode(source) {
    let result = "", index = 0;
    const blank = (end) => { result += source.slice(index, end).replace(/[^\n]/g, " "); index = end; };
    while (index < source.length) {
        if (source.startsWith("//", index)) { const end = source.indexOf("\n", index); blank(end < 0 ? source.length : end); continue; }
        if (source.startsWith("/*", index)) {
            let depth = 1, end = index + 2;
            while (end < source.length && depth) {
                if (source.startsWith("/*", end)) { depth++; end += 2; }
                else if (source.startsWith("*/", end)) { depth--; end += 2; }
                else end++;
            }
            if (depth) throw new Error("Unterminated Rust comment in audited source");
            blank(end); continue;
        }
        const raw = /^(?:br|r)(#{0,255})"/.exec(source.slice(index));
        if (raw && (index === 0 || !/[A-Za-z0-9_]/.test(source[index - 1]))) {
            const closing = `"${raw[1]}`;
            const end = source.indexOf(closing, index + raw[0].length);
            if (end < 0) throw new Error("Unterminated Rust raw literal in audited source");
            blank(end + closing.length); continue;
        }
        if (source[index] === '"') {
            let end = index + 1;
            while (end < source.length && source[end] !== '"') { if (source[end] === "\\") end++; end++; }
            if (end >= source.length) throw new Error("Unterminated Rust literal in audited source");
            blank(end + 1); continue;
        }
        const character = /^'(?:\\(?:u\{[a-fA-F0-9_]+\}|x[a-fA-F0-9]{2}|.)|[^'\\\r\n])'/u.exec(source.slice(index));
        if (character) { blank(index + character[0].length); continue; }
        result += source[index++];
    }
    return result;
}

export function validateTestAuditProposal(proposal) {
    const { test, fault } = proposal;
    if (!["existing-test-strengthening", "existing-test-sensitivity"].includes(proposal.purpose) || proposal.repository !== "omg-cli/omg" ||
        proposal.branch !== "main" || !/^[a-f0-9]{40}$/.test(proposal.baseSha) ||
        !(test.target === "lib" ? /^src\/(?:[A-Za-z0-9_-]+\/)*[A-Za-z0-9_.-]+\.rs$/ : /^tests\/[A-Za-z0-9_-]+\.rs$/).test(test.path) ||
        (test.target !== undefined && test.target !== "lib") ||
        !/^[A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)*$/.test(test.testName) ||
        !/^src\/(?:[A-Za-z0-9_-]+\/)*[A-Za-z0-9_.-]+\.rs$/.test(fault.path))
        throw new Error("Invalid existing-test audit identity");
    for (const file of [test, fault])
        if (typeof file.newContent !== "string" || !file.newContent || file.newContent.length > 256 * 1024 ||
            Buffer.byteLength(file.newContent) > 256 * 1024 || file.newContent.includes("\0") || !/^[a-f0-9]{40}$/.test(file.originalBlobSha) ||
            auditHash(file.newContent) !== file.sha256)
            throw new Error("Invalid audit file bytes");
    if (typeof test.originalContent !== "string" || !test.originalContent || test.originalContent.length > 256 * 1024 ||
        Buffer.byteLength(test.originalContent) > 256 * 1024 || test.originalContent.includes("\0") || blob(test.originalContent) !== test.originalBlobSha ||
        !Number.isSafeInteger(test.assertionLine) || test.assertionLine < 1 ||
        typeof fault.oldContentQuote !== "string" || !fault.oldContentQuote || fault.oldContentQuote.length > 4000)
        throw new Error("Invalid original test identity or assertion");
    const before = test.originalContent;
    const after = test.newContent;
    const lines = after.match(/[^\n]*\n|[^\n]+$/g) ?? [];
    const insertion = lines[test.assertionLine - 1] ?? "";
    if (proposal.purpose === "existing-test-sensitivity") {
        if (before !== after || !/^[ \t]*assert(?:_eq|_ne)?!\(/.test(insertion))
            throw new Error("Sensitivity verification requires the unchanged existing assertion");
    } else if (lines.filter((_, index) => index !== test.assertionLine - 1).join("") !== before ||
        !/^[ \t]*assert(?:_eq|_ne)?!\([^\r\n;{}#]*\);\r?\n$/.test(insertion) ||
        /\/\/|\/\*|\*\/|\b(?:return|break|continue|unsafe)\b/.test(insertion) ||
        !after.split(/\r?\n/)[test.assertionLine - 1]?.match(/^\s*assert(?:_eq|_ne)?!\(/))
        throw new Error("Strengthening must insert one additional assertion without changing existing test bytes");
    const code = rustCode(before);
    const leaf = test.testName.split("::").at(-1);
    const definitions = [...code.matchAll(new RegExp(`\\bfn\\s+${leaf}\\s*\\(`, "g"))];
    const position = lines.slice(0, test.assertionLine - 1).join("").length;
    if (definitions.length !== 1) throw new Error("Audit test function must have one unambiguous source definition");
    const start = code.indexOf("{", definitions[0].index);
    let depth = 1, end = start + 1;
    while (start >= 0 && end < code.length && depth) { if (code[end] === "{") depth++; else if (code[end] === "}") depth--; end++; }
    if (start < 0 || depth || position <= start || position >= end ||
        (test.target === "lib" && !/#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]/.test(code.slice(0, definitions[0].index))))
        throw new Error("Additional assertion must be inside the designated existing test body");
    return proposal;
}

export function testAuditPhaseSource(proposal, phase) {
    const old = phase.startsWith("old");
    if (proposal.test.path !== proposal.fault.path || !phase.endsWith("Fault"))
        return old ? proposal.test.originalContent : proposal.test.newContent;
    if (old) return proposal.fault.newContent;
    const lines = proposal.fault.newContent.match(/[^\n]*\n|[^\n]+$/g) ?? [];
    const assertion = (proposal.test.newContent.match(/[^\n]*\n|[^\n]+$/g) ?? [])[proposal.test.assertionLine - 1];
    lines.splice(proposal.test.assertionLine - 1, 0, assertion);
    return lines.join("");
}

export async function runTestAuditStates(proposal, controller) {
    validateTestAuditProposal(proposal);
    const results = {};
    try {
        for (const phase of testAuditPhasesFor(proposal)) {
            const old = phase.startsWith("old");
            await controller.writeTest(old ? proposal.test.originalContent : proposal.test.newContent);
            await controller.writeFault(phase.endsWith("Fault"), phase);
            await controller.verify(phase);
            const result = await controller.run(phase);
            await controller.verify(phase);
            const red = proposal.purpose === "existing-test-sensitivity" ? phase === "oldFault" : phase === "strongerFault";
            if (result.exitCode !== (red ? 101 : 0) || result.failures !== (red ? 1 : 0) ||
                result.tests !== 1 || result.errors !== 0 || result.skipped !== 0 ||
                result.testName !== proposal.test.testName ||
                result.sourceSha256 !== auditHash(testAuditPhaseSource(proposal, phase)) ||
                (results.oldIntact && result.recipeSha256 !== results.oldIntact.recipeSha256) ||
                (red && (result.assertionFile !== proposal.test.path || result.assertionLine !== proposal.test.assertionLine ||
                    result.assertionSourceSha256 !== auditHash(proposal.test.newContent.split(/\r?\n/)[proposal.test.assertionLine - 1]))))
                throw new Error(`Existing-test audit ${phase} did not reach its required outcome`);
            results[phase] = result;
        }
        return results;
    } finally {
        await controller.writeFault(false);
    }
}
