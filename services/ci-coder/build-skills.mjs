import { createHash } from "node:crypto";
import { readFile, readdir, writeFile } from "node:fs/promises";
import path from "node:path";

const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
const canonical = (value) => JSON.stringify(value, (_, item) =>
  item && !Array.isArray(item) && Object.getPrototypeOf(item) === Object.prototype
    ? Object.fromEntries(Object.entries(item).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0))
    : item);

// Retain the original CodeLoud package registry and append the required Rust guidance.
export async function buildSkills({ rust, tdd, destination = path.resolve(import.meta.dir, "../../vendor/ci-coder-skills") }) {
  const bundle = JSON.parse(await readFile(path.join(destination, "bundle.json"), "utf8"));
  for (const file of Object.values(bundle.files)) {
    if (Buffer.byteLength(file.content) !== file.bytes || digest(file.content) !== file.sha256)
      throw new Error("Existing skill registry has changed without matching provenance");
  }
  async function include(root, namespace, relative, version) {
    const bytes = await readFile(path.join(root, relative));
    const id = `${namespace}/${relative.replaceAll(path.sep, "/")}`;
    const origin = namespace === "rust" ? `rust-best-practices@${version}`
      : relative === "LICENSE" ? `superpowers@${version}`
      : `superpowers@${version}/skills/test-driven-development`;
    bundle.files[id] = { content: bytes.toString("utf8"), sha256: digest(bytes), bytes: bytes.length,
      source: `${origin}/${relative.replaceAll(path.sep, "/")}#sha256=${digest(bytes)}` };
  }
  await include(rust, "rust", "SKILL.md", "1.1.2");
  for (const entry of await readdir(path.join(rust, "references"), { withFileTypes: true })) {
    if (entry.isSymbolicLink() || !entry.isFile()) throw new Error("Unexpected Rust reference type");
    if (entry.name.endsWith(".md")) await include(rust, "rust", `references/${entry.name}`, "1.1.2");
  }
  await include(tdd, "tdd", "SKILL.md", "6.4.2");
  await include(path.resolve(tdd, "../.."), "tdd", "LICENSE", "6.4.2");
  const adapter = await readFile(path.join(import.meta.dir, "skills/workerd/ADAPTER.md"));
  bundle.files["workerd/ADAPTER.md"] = { content: adapter.toString("utf8"), sha256: digest(adapter),
    bytes: adapter.length, source: "omg-workerd-adapter@1" };
  bundle.packages = { ...bundle.packages, rust: "1.1.2", tdd: "6.4.2" };
  bundle.required = ["pstack/skills/poteto-mode/SKILL.md", "ponytail/skills/ponytail/SKILL.md",
    "workerd/ADAPTER.md", "rust/SKILL.md", "tdd/SKILL.md"];
  const metadata = Object.fromEntries(Object.entries(bundle.files).map(([id, file]) =>
    [id, { sha256: file.sha256, bytes: file.bytes, source: file.source }]));
  const manifest = { version: 1, packages: bundle.packages, required: bundle.required, files: metadata };
  const bundleSha256 = digest(canonical(manifest));
  await writeFile(path.join(destination, "manifest.json"), JSON.stringify({ ...manifest, bundleSha256 }, null, 2) + "\n");
  await writeFile(path.join(destination, "bundle.json"), JSON.stringify({ ...manifest, files: bundle.files, bundleSha256 }, null, 2) + "\n");
  return { bundleSha256, files: Object.keys(bundle.files).length };
}

if (import.meta.main) {
  const [rust, tdd] = process.argv.slice(2);
  if (!rust || !tdd) throw new Error("Usage: bun build-skills.mjs <rust-skill-root> <tdd-skill-root>");
  console.log(JSON.stringify(await buildSkills({ rust, tdd })));
}
