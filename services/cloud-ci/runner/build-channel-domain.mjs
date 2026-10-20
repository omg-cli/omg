const release = Object.freeze({
  channel: "release",
  appName: "Codeloud Bun Alpha",
  identifier: "cloud.codeloud.bun.alpha",
  ownerFeatures: false,
});

const prerelease = Object.freeze({
  channel: "prerelease",
  appName: "Codeloud Prerelease",
  identifier: "cloud.codeloud.prerelease",
  ownerFeatures: true,
});

/** @param {unknown} [value] */
export function buildChannel(value) {
  if (value === undefined || value === "release") return release;

  if (value === "prerelease") return prerelease;
  throw new Error("Invalid Codeloud build channel.");
}
