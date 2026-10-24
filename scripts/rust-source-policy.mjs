import { createHash } from "node:crypto";

const testBoundary =
    /#\s*\[\s*(?:cfg(?:_attr)?\b[^\]]*\btest\b[^\]]*|(?:[A-Za-z_][A-Za-z0-9_]*::)*test\b[^\]]*)\]/;
const attributes = (source) => source.match(/#\s*!?\s*\[[\s\S]*?\]/g) ?? [];

const reviewedHelperCfgs = new Map([
    [
        "src/cli/packages/explicit.rs",
        {
            sha256: "c7ae9b268a77ab2a3ce70fd9be05c86dbb92af2ef1753a890e9eaff82eb7871e",
            attributes: [
                `#[cfg(any(
    not(any(feature = "arch", feature = "debian", feature = "debian-pure")),
    test
))]`,
            ],
        },
    ],
    [
        "src/cli/packages/clean.rs",
        {
            sha256: "bc527603b187ef07261eb9da91556a751dcb88f9bc19f7f3402a8104c0a3fa7d",
            attributes: [
                `#[cfg(any(test, feature = "debian"))]`,
                `#[cfg(any(test, feature = "debian-pure"))]`,
            ],
        },
    ],
]);

const sha256 = (source) => createHash("sha256").update(source, "utf8").digest("hex");

function boundaryOf(source, file) {
    const pin = reviewedHelperCfgs.get(file);
    const exempt =
        pin && sha256(source) === pin.sha256 ? new Set(pin.attributes) : new Set();
    for (const match of source.matchAll(new RegExp(testBoundary.source, "g"))) {
        if (!exempt.has(match[0])) return match.index;
    }
    return -1;
}

export function assertRustSourceChange(file, original, updated) {
    if (
        !/^src\/(?:[A-Za-z0-9_-]+\/)*[A-Za-z0-9_.-]+\.rs$/.test(file) ||
        /(?:^|\/)tests?\.rs$/.test(file)
    )
        throw new Error("Automatic repairs require production Rust source");
    if (JSON.stringify(attributes(original)) !== JSON.stringify(attributes(updated)))
        throw new Error("Rust conditional attributes and lint policy must remain unchanged");
    const boundary = boundaryOf(original, file);
    if (boundary >= 0 && !updated.endsWith(original.slice(boundary)))
        throw new Error("Automatic repairs cannot change existing Rust tests");
    if (boundary < 0 && testBoundary.test(updated))
        throw new Error("New regressions must use the designated separate test file");
}
