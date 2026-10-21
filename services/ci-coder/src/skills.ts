import type { Plugin } from "@opencode/plugin";
import type { SessionContext } from "@opencode/plugin/promise/session";
import { Skill } from "@opencode/schema/skill";
import { Schema } from "effect";
import bundledSkills from "../../../vendor/ci-coder-skills/bundle.json";

export type SkillBundle = {
  version: number;
  packages: Record<string, string>;
  required: string[];
  files: Record<string, { content: string; sha256: string; bytes: number; source: string }>;
  bundleSha256: string;
};

const required = [
  "pstack/skills/poteto-mode/SKILL.md",
  "ponytail/skills/ponytail/SKILL.md",
  "workerd/ADAPTER.md",
  "rust/SKILL.md",
  "rust-async/SKILL.md",
  "tdd/SKILL.md",
];

const canonical = (value: {
  version: number;
  packages: SkillBundle["packages"];
  required: string[];
  files: Record<string, { sha256: string; bytes: number; source: string }>;
}) =>
  JSON.stringify(value, (_, item) =>
    item && !Array.isArray(item) && Object.getPrototypeOf(item) === Object.prototype
      ? Object.fromEntries(Object.entries(item).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)))
      : item,
  );

const digest = async (value: string) =>
  [...new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)))]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");

export const requiredSkillsManifest = Object.freeze({
  bundleSha256: bundledSkills.bundleSha256,
  packages: Object.freeze({ ...bundledSkills.packages }),
  required: Object.freeze([...required]),
});

type SkillContext = Pick<SessionContext, "sessionID" | "system">;

type ContextKind = "context" | "compaction" | "generate";

export async function registerRequiredSkillContexts(
  register: (
    kind: ContextKind,
    callback: (context: SkillContext) => void,
  ) => Promise<{ dispose(): Promise<void> }>,
  inject: (context: SkillContext) => void,
) {
  return [
    await register("context", inject),
    await register("compaction", inject),
    await register("generate", inject),
  ];
}

export async function assertRequiredSkillsBundle(bundle: SkillBundle = bundledSkills) {
  if (
    bundle.version !== 1 ||
    bundle.packages.pstack !== "0.15.2+codex.20260922221615" ||
    bundle.packages.ponytail !== "5.3.2" ||
    bundle.packages.rust !== "1.1.2" ||
    bundle.packages["rust-async"] !== "156b7a5e7a8b93642628a339ee4039c925b34c7f" ||
    bundle.packages.tdd !== "6.4.2" ||
    JSON.stringify(bundle.required) !== JSON.stringify(required) ||
    bundle.bundleSha256 !== bundledSkills.bundleSha256
  )
    throw new Error("Required skill policy differs from the pinned bundle");

  for (const id of required)
    if (!bundle.files[id]?.content) throw new Error("Required skill entry is missing");
  const metadata: Record<string, { sha256: string; bytes: number; source: string }> = {};

  for (const [id, file] of Object.entries(bundle.files)) {
    if (
      !/^(?:pstack|ponytail|workerd|rust|rust-async|tdd)\/(?:[A-Za-z0-9_.-]+\/)*[A-Za-z0-9_.-]+$/.test(id) ||
      id.split("/").some((segment) => segment === "." || segment === "..")
    )
      throw new Error("Invalid skill registry path");

    if (
      new TextEncoder().encode(file.content).length !== file.bytes ||
      (await digest(file.content)) !== file.sha256
    )
      throw new Error("Skill source hash mismatch");
    metadata[id] = { sha256: file.sha256, bytes: file.bytes, source: file.source };
  }

  if (
    (await digest(
      canonical({
        version: bundle.version,
        packages: bundle.packages,
        required: bundle.required,
        files: metadata,
      }),
    )) !== bundle.bundleSha256
  )
    throw new Error("Skill manifest hash mismatch");
}

export async function createRequiredSkillsPlugin(bundle: SkillBundle = bundledSkills) {
  const snapshot: SkillBundle = structuredClone(bundle);
  await assertRequiredSkillsBundle(snapshot);
  const delivered = new Set<string>();

  const injectedText =
    "Required coding skills are automatically active. Apply the Workerd adapter when platform-specific instructions differ.\n\n" +
    snapshot.required.map((id) => `--- ${id} ---\n${snapshot.files[id].content}`).join("\n\n");

  const contextHook = (context: Pick<SessionContext, "sessionID" | "system">) => {
    context.system.unshift({ type: "text", text: injectedText });
    delivered.add(context.sessionID);
  };

  const plugin: Plugin.Plugin = {
    id: "omg-required-skills",
    async setup(context) {
      const registrations = [
        await context.skill.transform((editor) => {
          for (const [index, id] of required.filter((id) => id !== "workerd/ADAPTER.md").entries())
            editor.add(
              Schema.decodeUnknownSync(Skill.Info)({
                id: `omg-required-${index}`,
                name: id === "rust/SKILL.md" ? "rust-best-practices" : id === "rust-async/SKILL.md" ? "rust-async-patterns" : id === "tdd/SKILL.md" ? "test-driven-development" : index === 0 ? "poteto-mode" : "ponytail",
                description: "Mandatory versioned coding guidance",
                autoinvoke: true,
                path: `/__omg_skills/${id}`,
                content: snapshot.files[id].content,
              }),
            );
        }),
        ...(await registerRequiredSkillContexts(context.session.hook, contextHook)),
      ];

      return async () => {
        for (const registration of registrations) await registration.dispose();
        delivered.clear();
      };
    },
  };

  return {
    plugin,
    bundleSha256: snapshot.bundleSha256,
    assertDelivered(sessionId?: string) {
      const id = sessionId ?? (delivered.size === 1 ? delivered.values().next().value : undefined);

      if (!id || !delivered.has(id))
        throw new Error("Mandatory skill bundle has not been delivered to this session");

      return { bundleSha256: snapshot.bundleSha256, sessionId: id };
    },
    contextHook,
    read(id: string, from?: string) {
      if (
        !id ||
        id.startsWith("/") ||
        /[\\:]/.test(id) ||
        id.split("").some((character) => character.charCodeAt(0) < 32)
      )
        throw new Error("Invalid virtual skill reference");
      const parts = from ? from.split("/").slice(0, -1) : [];

      if (from && !snapshot.files[from]) throw new Error("Unknown skill reference origin");

      for (const part of id.split("/")) {
        if (part === ".") continue;

        if (part === "..") {
          if (parts.length <= 1) throw new Error("Skill reference escapes its package");
          parts.pop();
        } else {
          if (!/^[A-Za-z0-9_.-]+$/.test(part)) throw new Error("Invalid virtual skill reference");
          parts.push(part);
        }
      }

      const file = snapshot.files[parts.join("/")];

      if (!file) throw new Error("Skill reference is not in the bundled registry");

      return file.content;
    },
  };
}

export type RequiredSkills = Awaited<ReturnType<typeof createRequiredSkillsPlugin>>;
