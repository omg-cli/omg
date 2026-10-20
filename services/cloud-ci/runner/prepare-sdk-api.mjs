import { execFileSync } from "node:child_process";
import { mkdir, realpath, writeFile } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { Schema } from "effect";

const sdkDirectories = Schema.Struct({
  sourceDirectory: Schema.String,
  outputDirectory: Schema.String,
});

const upstreamCommit = "c4bbeca07829d9b1634d31598ef6091fb19ace2a";
const version = "2.0.3-beta.26";

const prefixes = [
  "package/src/sdks/main/",
  "package/src/browser/",
  "package/src/shared/",
  "package/src/config/",
  "package/src/preload/",
];

const sourcePaths = [...prefixes.map((prefix) => prefix.slice(0, -1)), "LICENSE"];
const maxBytes = 16 * 1024 * 1024;

export async function prepareSdkApi({ sourceDirectory, outputDirectory }) {
  if (!Schema.is(sdkDirectories)({ sourceDirectory, outputDirectory }))
    throw new Error("Supply sourceDirectory and outputDirectory.");
  const source = await realpath(sourceDirectory);
  const requestedOutput = path.resolve(outputDirectory);

  const output = path.join(
    await realpath(path.dirname(requestedOutput)),
    path.basename(requestedOutput),
  );

  const relative = path.relative(source, output);

  if (
    !relative ||
    (!relative.startsWith(`..${path.sep}`) && relative !== ".." && !path.isAbsolute(relative))
  )
    throw new Error("The API output must be outside the SDK source directory.");

  const git = (...args) =>
    execFileSync("git", ["-C", source, ...args], {
      windowsHide: true,
      timeout: 15_000,
      maxBuffer: maxBytes,
      stdio: ["ignore", "pipe", "pipe"],
    });

  if (git("rev-parse", "HEAD").toString("utf8").trim() !== upstreamCommit)
    throw new Error("The SDK source must be checked out at the pinned commit.");

  const metadata = JSON.parse(
    git("show", `${upstreamCommit}:package/package.json`).toString("utf8"),
  );

  if (metadata.version !== version)
    throw new Error("The SDK version does not match the pinned API.");
  const expected = new Map();
  const tree = git("ls-tree", "-r", "-z", upstreamCommit, "--", ...sourcePaths).toString("utf8");

  for (const record of tree.split("\0").filter(Boolean)) {
    const match = /^(100644|100755) blob [0-9a-f]{40}\t(.+)$/.exec(record);

    if (!match) throw new Error("The pinned SDK API contains an unsupported file mode.");
    const name = match[2];

    if (
      name.includes("\\") ||
      name.includes(":") ||
      name.split("/").some((part) => part === ".." || part === ".")
    )
      throw new Error("The pinned SDK API contains an invalid path.");

    if (name !== "LICENSE" && !prefixes.some((prefix) => name.startsWith(prefix)))
      throw new Error("The pinned SDK API contains an unexpected path.");
    expected.set(name, name === "LICENSE" ? name : name.slice("package/src/".length));
  }

  if (expected.size !== 206) throw new Error("The pinned SDK API file inventory does not match.");

  const archive = await new Bun.Archive(
    git("archive", "--format=tar", upstreamCommit, "--", ...sourcePaths),
  ).files();

  if (archive.size !== expected.size || [...archive.keys()].some((name) => !expected.has(name)))
    throw new Error("The SDK archive does not match its pinned file inventory.");
  let total = 0;

  for (const file of archive.values()) {
    total += file.size;

    if (file.size > 2 * 1024 * 1024 || total > maxBytes)
      throw new Error("The SDK API archive exceeds its source size bound.");
  }

  await mkdir(output);

  for (const [name, file] of archive) {
    const destination = path.join(output, expected.get(name));
    await mkdir(path.dirname(destination), { recursive: true });
    await writeFile(destination, new Uint8Array(await file.arrayBuffer()), { flag: "wx" });
  }

  const preload = async (entry) => {
    const result = await Bun.build({
      entrypoints: [path.join(output, "preload", entry)],
      target: "browser",
      format: "esm",
      minify: false,
    });

    if (!result.success || result.outputs.length !== 1)
      throw new Error(`SDK preload compilation failed: ${entry}`);

    return `(function(){${await result.outputs[0].text()}})();`;
  };

  const full = await preload("index.ts");
  const sandboxed = await preload("index-sandboxed.ts");
  const generated = path.join(output, "preload", ".generated");
  await mkdir(generated);
  await writeFile(
    path.join(generated, "compiled.ts"),
    `export const preloadScript = ${JSON.stringify(full)};

export const preloadScriptSandboxed = ${JSON.stringify(sandboxed)};
`,
    { flag: "wx" },
  );

  return { upstreamCommit, version, copiedFiles: expected.size, generatedFiles: 1 };
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  try {
    const args = process.argv.slice(2);

    if (args.length !== 4 || args[0] !== "--source" || args[2] !== "--out")
      throw new Error(
        "Usage: bun scripts/prepare-sdk-api.mjs --source <SDK checkout> --out <new API directory>",
      );
    console.log(
      JSON.stringify(await prepareSdkApi({ sourceDirectory: args[1], outputDirectory: args[3] })),
    );
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
