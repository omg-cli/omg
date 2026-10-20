import { buildChannel } from "./build-channel-domain.mjs";

export { buildChannel };

/** @param {unknown} html @param {unknown} channel */
export function assertRendererBuildChannel(html, channel) {
  const expected = buildChannel(channel);

  const markers = Schema.is(rendererDocument)(html)
    ? [...html.matchAll(/<meta\s+name="codeloud-build-channel"\s+content="([^"]*)"\s*\/?>/g)]
    : [];

  if (markers.length !== 1 || markers[0][1] !== expected.channel)
    throw new Error("Codeloud renderer build does not match its application channel.");
}

/** @param {unknown} input */
export function parseBuildChannel(input) {
  if (
    !Schema.is(channelMarker)(input) ||
    Object.keys(input).length !== 3 ||
    Object.keys(input).some((key) => !["channel", "identifier", "ownerFeatures"].includes(key)) ||
    !("channel" in input) ||
    !("identifier" in input) ||
    !("ownerFeatures" in input) ||
    (input.channel !== "release" && input.channel !== "prerelease")
  )
    throw new Error("Invalid Codeloud build channel marker.");
  const expected = buildChannel(input.channel);

  if (input.identifier !== expected.identifier || input.ownerFeatures !== expected.ownerFeatures)
    throw new Error("Invalid Codeloud build channel marker.");

  return expected;
}

import { Schema } from "effect";

const rendererDocument = Schema.String.check(Schema.makeFilter((html) => html.includes("<meta")));

const channelMarker = Schema.Struct({
  channel: Schema.Literals(["release", "prerelease"]),
  identifier: Schema.String,
  ownerFeatures: Schema.Boolean,
});
