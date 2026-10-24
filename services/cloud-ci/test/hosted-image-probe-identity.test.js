import { describe, expect, test } from "bun:test";
import { validateImageIdentity } from "./hosted-image-probe.mjs";

const CONFIG = "sha256:1272b61d648725d46531d6c6b49c1610cec3fa2168430ebb2b2487b266c4ea2b";
const MANIFEST = "sha256:95c9a1dcbc052716443f382b4f23766a6af1301d1f41dddc640c0ddbdf597a16";
const OTHER = "sha256:" + "f".repeat(64);
const REFERENCE = "registry.cloudflare.com/f1e95b3e1b502cf366dfc81a863695fa/omg-cloud-ci";
const REPO_DIGESTS = [REFERENCE + "@" + MANIFEST];
const CONTAINERD = 'overlayfs/[["driver-type","io.containerd.snapshotter.v1"]]';
const LEGACY = 'overlay2/[["Backing Filesystem","extfs"]]';
const RAW_JSON = JSON.stringify({
    schemaVersion: 2,
    mediaType: "application/vnd.oci.image.manifest.v1+json",
    config: { mediaType: "application/vnd.oci.image.config.v1+json", digest: CONFIG, size: 123 },
    layers: [],
});
const RAW = Buffer.from(RAW_JSON, "utf8").toString("base64");

function fixture(backend) {
    const containerd = backend === "containerd";
    const image = {
        Id: containerd ? MANIFEST : CONFIG,
        RepoDigests: [...REPO_DIGESTS],
        Os: "linux",
        Architecture: "amd64",
    };
    if (containerd) image.Descriptor = {
        mediaType: "application/vnd.oci.image.manifest.v1+json",
        digest: MANIFEST,
        size: 9792,
        annotations: { "config.digest": CONFIG },
    };
    return {
        localId: image.Id,
        image,
        manifest: {
            Descriptor: { mediaType: "application/vnd.oci.image.manifest.v1+json", digest: MANIFEST, size: RAW_JSON.length },
            Raw: RAW,
            OCIManifest: { config: { digest: CONFIG } },
        },
        backend: containerd ? CONTAINERD : LEGACY,
        registryReference: REFERENCE,
        repoDigests: [...REPO_DIGESTS],
    };
}

function changed(backend, mutate) {
    const value = fixture(backend);
    mutate(value);
    return value;
}

const cases = [
    ["accepts the observed containerd identity chain", () => fixture("containerd"), null],
    ["accepts the legacy config identity", () => fixture("legacy"), null],
    ["rejects a local image id that differs from metadata", () => changed("containerd", (value) => { value.localId = OTHER; }), "local image metadata id mismatch"],
    ["rejects config identity on confirmed containerd even when local metadata agrees", () => changed("containerd", (value) => { value.localId = value.image.Id = CONFIG; }), "containerd identity mismatch"],
    ["rejects manifest identity on legacy even when local metadata agrees", () => changed("legacy", (value) => { value.localId = value.image.Id = MANIFEST; }), "local image id config mismatch"],
    ["rejects containerd without its local descriptor", () => changed("containerd", (value) => { delete value.image.Descriptor; }), "local image descriptor missing"],
    ["rejects a local index even when the remote is a single manifest", () => changed("containerd", (value) => { value.image.Descriptor.mediaType = "application/vnd.oci.image.index.v1+json"; }), "local image descriptor was not a single image manifest"],
    ["rejects a local descriptor digest that differs from the manifest", () => changed("containerd", (value) => { value.image.Descriptor.digest = OTHER; }), "local image descriptor digest mismatch"],
    ["rejects a verbose config digest that differs from the raw config", () => changed("containerd", (value) => { value.manifest.OCIManifest.config.digest = OTHER; }), "raw manifest config mismatch"],
    ["rejects raw bytes that do not hash to the manifest digest", () => changed("containerd", (value) => { value.manifest.Raw = Buffer.from(RAW_JSON.replace('"size":123', '"size":124'), "utf8").toString("base64"); }), "raw manifest digest mismatch"],
    ["rejects a missing exact registry linkage", () => changed("containerd", (value) => { value.repoDigests = []; }), "local registry linkage missing"],
    ["rejects an array of manifests", () => changed("containerd", (value) => { value.manifest = []; }), "registry manifest was not a single object"],
    ["rejects an index descriptor", () => changed("containerd", (value) => { value.manifest.Descriptor.mediaType = "application/vnd.oci.image.index.v1+json"; }), "registry descriptor was not a single image manifest"],
    ["rejects an unknown storage backend", () => changed("containerd", (value) => { value.backend = "overlayfs/[]"; }), "storage backend was not recognized"],
    ["rejects a descriptor config annotation that differs from the verbose config", () => changed("containerd", (value) => { value.image.Descriptor.annotations["config.digest"] = OTHER; }), "local image descriptor config mismatch"],
];

describe("hosted image identity validation", () => {
    for (const [name, build, error] of cases) {
        test(name, () => {
            if (error === null) expect(validateImageIdentity(build())).toEqual({ digest: MANIFEST, config: CONFIG, repoDigest: REFERENCE + "@" + MANIFEST });
            else expect(() => validateImageIdentity(build())).toThrow(error);
        });
    }
});
