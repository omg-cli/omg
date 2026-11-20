import { parse } from "yaml";

declare namespace matter {
    interface GrayMatterFile<Input extends string> {
        orig: Input;
        data: Record<string, unknown>;
        content: string;
    }
}

// OpenCode only uses the parsed mapping and Markdown body. Keep the language
// limited to data formats and reject YAML aliases.
function matter<Input extends string>(
    source: Input,
    options: { language?: string } = {},
): matter.GrayMatterFile<Input> {
    const lines = source.split("\n");
    const marker = lines[0]?.replace(/^\uFEFF/u, "").trimEnd();
    if (!marker?.startsWith("---") || marker.startsWith("----")) {
        return { orig: source, content: source, data: {} };
    }

    const tag = marker.slice(3).trim();
    const language = tag || options.language || "yaml";
    if (language !== "yaml" && language !== "json") {
        throw new Error("Only YAML and JSON frontmatter are supported");
    }

    const end = lines.findIndex((line, index) => index > 0 && line.trimEnd() === "---");
    if (end === -1) throw new Error("Unclosed frontmatter");
    const header = lines.slice(1, end)
        .map((line) => line.endsWith("\r") ? line.slice(0, -1) : line)
        .join("\n");
    const value: unknown = language === "json" ? JSON.parse(header) : parse(header, { maxAliasCount: 0 });
    if (value == null) return { orig: source, content: lines.slice(end + 1).join("\n"), data: {} };
    if (typeof value !== "object" || Array.isArray(value)) {
        throw new Error("Frontmatter must contain a mapping");
    }
    return {
        orig: source,
        data: Object.fromEntries(Object.entries(value)),
        content: lines.slice(end + 1).join("\n"),
    };
}

export default matter;
