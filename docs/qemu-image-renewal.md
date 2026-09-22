---
title: QEMU image review
sidebar_position: 64
description: Renew reviewed image pins before QEMU provenance expires
---

# Reviewing QEMU images

> **Who this page is for:** OMG maintainers and contributors. It documents refreshing the virtual-machine images.
> It is not an everyday user guide. If you are new to OMG, start with
> [Getting started](./getting-started.md).

Image provenance expires after at most 31 days. The daily **QEMU Pin Review** workflow checks the manifest on `main` and opens one maintenance issue when seven days or fewer remain. It does not renew dates, download executable code, replace keys, or merge changes. An expired review prevents the verifier from accepting an image.

Prepare a review PR before the deadline:

1. Read the publisher source recorded for each image in `tests/qemu-image-provenance/manifest.json`. Check image availability, supported release status and published security updates. Review the [Debian QEMU security tracker](https://security-tracker.debian.org/tracker/source-package/qemu) against the controller package versions recorded by recent QEMU runs. Increase the controller floor when required; a minimum version is not a claim that future vulnerabilities cannot exist.
2. Obtain versioned image URLs and checksum/signature material from the publisher. Preserve the pinned primary key fingerprints. Verify a proposed key rotation against the publisher's official security documentation in a separate, explicit review. Do not trust a new key just because it accompanied a download.
3. Stage changed public verification material in `tests/qemu-image-provenance/`. Update the driver pins and matching manifest entries together. For Debian cloud images retain the explicit unsigned-checksum exception unless Debian actually publishes equivalent signatures; CD signing documentation does not prove cloud-image authenticity.
4. Run `python3 scripts/verify-qemu-image.py --manifest tests/qemu-image-provenance/manifest.json --identity DISTRO-ARCH --url URL --digest DIGEST --image DOWNLOADED_IMAGE` for each changed image. This checks image bytes and the manifest's verification policy before QEMU parses it. Signed publishers require the pinned key and signature binding. Debian's explicit unsigned cloud-checksum exception returns `signature_verified: false`. Keep verification receipts with the review. Never substitute a checksum-only fallback for a signed publisher.
5. After completing the review, set `reviewed_on` to the current UTC date and `review_expires` no more than 31 days later. Run `python3 -m unittest discover -s scripts -p 'test_qemu_*.py'` on Linux and `python3 scripts/check-qemu-review.py`.
6. Run the QEMU Matrix for all supported x86_64 images using the candidate branch. Validate ARM images on the configured trusted ARM runner before claiming ARM execution coverage. Include the run URLs, image-provenance receipts, controller version receipts, changed pins and any documented exceptions in the PR.

Changing only a date is acceptable only when the same review establishes that the existing pins remain suitable and their artifacts remain available. A passing fixture test alone does not establish this. Expired metadata keeps the release gate closed until the review is merged; failures are not converted into skips.

## Where to go next

- [Local QEMU guide](./qemu-local.md) covers guest runs and evidence.
- [Release readiness](./release-readiness.md) lists the publication gates.
- [Troubleshooting](./troubleshooting.md) explains how to report failed checks.
