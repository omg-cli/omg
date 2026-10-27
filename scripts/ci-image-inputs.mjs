import { createHash } from "node:crypto";

const fixed = ["services/cloud-ci/Dockerfile", "services/cloud-ci/verifier.mjs",
    "scripts/rust-source-policy.mjs", "scripts/prepare-node-test-fixture.py",
    "scripts/test_qemu_boot_diagnostics.py", "scripts/qemu-boot-diagnostics.sh", "scripts/benchmark-qemu.sh",
    "scripts/test_qemu_cloud_init_ready.py", "scripts/check-qemu-cloud-init.sh"];

export async function ciImageInputsSha256(revision, readGit) {
    if (!/^[a-f0-9]{40}$/.test(revision)) throw new Error("Exact image source revision required");
    const dockerfile = await readGit(["show", `${revision}:services/cloud-ci/Dockerfile`]);
    for (const line of dockerfile.split(/\r?\n/)) {
        if (/^\s*ADD\s/i.test(line) || /^\s*RUN\s.*--mount(?:=|\s)/i.test(line))
            throw new Error("Unsupported Docker image input instruction");
        if (!/^\s*COPY\s/i.test(line)) continue;
        const sources = line.trim().split(/\s+/).slice(1, -1);
        if (line.includes("\\") || !sources.length || sources.some(source => source.split("/").some(p => p === "." || p === "..") ||
            (!fixed.includes(source) && !/^services\/cloud-ci\/runner\/(?:[A-Za-z0-9_.-]+\/)*[A-Za-z0-9_.-]*$/.test(source))))
            throw new Error("Unsupported Docker image COPY input");
    }
    const listing = await readGit(["ls-tree", "-r", "-z", revision, "--", "services/cloud-ci/runner", ...fixed]);
    const paths = listing.split("\0").filter(Boolean).map(record => {
        const match = /^(100644|100755) blob [a-f0-9]{40}\t([^\0]+)$/.exec(record);
        if (!match) throw new Error("Image inputs must be regular committed files");
        return match[2];
    });
    if (fixed.some(file => !paths.includes(file)) || !paths.some(file => file.startsWith("services/cloud-ci/runner/")))
        throw new Error("Required image inputs are missing");
    return createHash("sha256").update(listing).digest("hex");
}
