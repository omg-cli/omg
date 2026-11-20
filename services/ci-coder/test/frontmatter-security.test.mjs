import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { ConfigMarkdown } from "@opencode/core/config/markdown";
import matter from "../vendor/safe-frontmatter/index.ts";

test("the coder lock resolves a local, data-only frontmatter adapter", () => {
    const lock = readFileSync(new URL("../bun.lock", import.meta.url), "utf8");
    expect(lock).toContain('"@omg/safe-frontmatter@file:vendor/safe-frontmatter"');
    expect(lock).not.toContain('"gray-matter@4.0.3"');
});

test("frontmatter keeps YAML and JSON as data", () => {
    expect(ConfigMarkdown.parse("---\nname: audit\nenabled: true\n---\nBody").data)
        .toEqual({ name: "audit", enabled: true });
    expect(ConfigMarkdown.parse('---json\n{"name":"audit"}\n---\nBody').data)
        .toEqual({ name: "audit" });
    expect(ConfigMarkdown.parse("---\r\nname: audit\r\n---\r\nBody").content).toBe("Body");
});

test("frontmatter rejects executable formats even for a plain data literal", () => {
    const literal = '{"name":"audit"}';
    for (const language of ["js", "javascript"]) {
        expect(ConfigMarkdown.parseOption(`---${language}\n${literal}\n---\nBody`)).toBeUndefined();
        expect(() => matter(`---\n${literal}\n---`, { language }))
            .toThrow("Only YAML and JSON frontmatter are supported");
    }
});
