import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "bun:test";
import { Effect } from "effect";
import { z } from "zod/v4";
import { definition, execute } from "@opencode/core/tool/runtime";
import { Agent } from "@opencode/plugin";
import { Tool } from "@opencode/schema/tool";
import { Session } from "@opencode/schema/session";
import { SessionMessage } from "@opencode/schema/session-message";

const coreEntry = import.meta.resolve("@opencode/core/tool/runtime");
const coreRequire = createRequire(coreEntry);

function metadataVersion(entry: string): string {
  let directory = dirname(entry.startsWith("file:") ? fileURLToPath(entry) : entry);
  for (;;) {
    try {
      const metadata = JSON.parse(readFileSync(join(directory, "package.json"), "utf8"));
      if (typeof metadata.version === "string") return metadata.version;
    } catch (error) {
      if (!(error instanceof Error) || !("code" in error) || error.code !== "ENOENT") throw error;
    }
    const parent = dirname(directory);
    if (parent === directory) throw new Error(`Package metadata missing for ${entry}`);
    directory = parent;
  }
}

test("OpenCode keeps its compatible runtime with genuine patched dependencies", () => {
  assert.equal(metadataVersion(coreEntry), "2.1.1");
  assert.equal(metadataVersion(coreRequire.resolve("zod/v4")), "4.6.7");
  assert.equal(metadataVersion(coreRequire.resolve("gitlab-ai-provider")), "6.23.1");
  for (const name of ["@modelcontextprotocol/client", "@modelcontextprotocol/core"]) {
    assert.equal(metadataVersion(coreRequire.resolve(name)), "2.3.1");
  }
  for (const entry of [coreEntry, ...["@ai-sdk/cohere", "@ai-sdk/perplexity", "@ai-sdk/vercel", "@ai-sdk/openai-compatible"].map(name => coreRequire.resolve(name))]) {
    assert.equal(metadataVersion(createRequire(entry).resolve("@ai-sdk/provider-utils")), "4.0.33");
  }
});

test("OpenCode converts patched Zod schemas and rejects invalid tool arguments before execution", async () => {
  const input = z.object({ paths: z.array(z.string()).max(2), headers: z.record(z.string(), z.string()) });
  let calls = 0;
  const tool: Tool.Info<typeof input> = {
    name: "dependency_fixture", description: "Validate the installed tool schema boundary", input,
    execute: value => { calls++; return Effect.succeed({ content: JSON.stringify(value) }); },
  };
  const context: Tool.Context = {
    sessionID: Session.ID.make("ses_fixture"), agent: Agent.ID.make("build"),
    messageID: SessionMessage.ID.make("msg_fixture"), id: Tool.CallID.make("call_fixture"),
    progress: () => Effect.void,
  };
  const wire = definition(tool);
  assert.equal(wire.inputSchema.type, "object");
  const value = { paths: ["tests/value.rs"], headers: { "X-Arbitrary": "kept" } };
  const result = await Effect.runPromise(execute(tool, value, context));
  assert.deepEqual(result.content, [{ type: "text", text: JSON.stringify(value) }]);
  await assert.rejects(Effect.runPromise(execute(tool, { paths: ["a", "b", "c"], headers: {} }, context)), /Invalid arguments/);
  await assert.rejects(Effect.runPromise(execute(tool, { paths: [], headers: { malformed: 42 } }, context)), /Invalid arguments/);
  assert.equal(calls, 1);
});
