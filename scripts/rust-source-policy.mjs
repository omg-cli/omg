const testBoundary =
    /#\s*\[\s*(?:cfg(?:_attr)?\b[^\]]*\btest\b[^\]]*|(?:[A-Za-z_][A-Za-z0-9_]*::)*test\b[^\]]*)\]/;
const attributes = (source) => source.match(/#\s*!?\s*\[[\s\S]*?\]/g) ?? [];

export function assertRustSourceChange(file, original, updated) {
    if (
        !/^src\/(?:[A-Za-z0-9_-]+\/)*[A-Za-z0-9_.-]+\.rs$/.test(file) ||
        /(?:^|\/)tests?\.rs$/.test(file)
    )
        throw new Error("Automatic repairs require production Rust source");
    if (JSON.stringify(attributes(original)) !== JSON.stringify(attributes(updated)))
        throw new Error("Rust conditional attributes and lint policy must remain unchanged");
    const boundary = original.search(testBoundary);
    if (boundary >= 0 && !updated.endsWith(original.slice(boundary)))
        throw new Error("Automatic repairs cannot change existing Rust tests");
    if (boundary < 0 && testBoundary.test(updated))
        throw new Error("New regressions must use the designated separate test file");
}
