# Node Release Authentication Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Work solo in the existing checkout.

**Goal:** Refuse unauthenticated Node checksum manifests before any archive download or candidate execution.

**Architecture:** Verify the bounded clearsigned checksum manifest with the existing Sequoia backend and reviewed bundled Node certificates. Select the exact archive digest only from authenticated plaintext, preserving the existing download, retry and staging paths.

**Tech Stack:** Rust 1.95, existing Sequoia 2.4.1, reqwest metadata transport, existing HTTPS fixture and native Arch test target.

**Spec:** docs/superpowers/specs/2026-11-16-node-release-authentication.md

## Global Constraints

- Work solo in the existing main checkout; push only HEAD:codex/arch-hardening.
- No new dependency, unsigned fallback, automatic trust-authority refresh or user-keyring mutation.
- Bound signed input and plaintext to 1 MiB each; consume verified EOF before returning plaintext.
- Preserve current-time, weak-hash, expiration and revocation rejection.
- Preserve all checksum retry/integrity assertions and the original coverage/acceptance gates.
- Measure guest use and C-backed VHD/host capacity before native builds; preserve two workers and existing profiles.
- This is publisher authentication, not runtime advisory matching or zero-day detection.

## Review Focus

- A signed manifest containing a different release filename cannot authorize the requested archive.
- Correctly signed text with cleartext dash escaping/CRLF must verify without a handwritten canonicalizer.
- Missing detached sidecars must not cause unsigned fallback or rejection of a valid clearsigned manifest.
- Expired/revoked/unknown signers remain refused, including historical releases.
- Rejection must happen before archive download, publication, activation or candidate execution.

### Task 1: Admit public trust roots and interoperability fixtures

**Files:** Create src/runtimes/keys/node-release-keys.asc and its provenance README; create tests/fixtures/node-release-authentication/ with a real signed manifest and receipt. Add tests beside the Node verifier integration.

**Interfaces:** A fixed reviewed primary-fingerprint allowlist and embedded public certificate bytes; no runtime key download.

- [ ] Fetch the exact pinned key snapshot, verify blob hashes and actual primary fingerprints, reject secret/multiple/mismatched certificates, and cross-check current official signer listings.
- [ ] Record upstream commit/paths, SHA256s, license/provenance and the key-refresh review procedure. Verify source-package inclusion using the repository's existing packaging check.
- [ ] Add an interoperability test for the signed vendor fixture and exact archive filename/digest; ensure no runtime archive is downloaded/executed.

### Task 2: Bounded authenticated cleartext

**Files:** Modify src/core/security/pgp.rs and its existing test module.

**Interfaces:** PgpVerifier::verify_cleartext_memory(&self, signed: &[u8], max_plaintext: usize) -> Result<Vec<u8>, PgpError>. Existing detached APIs remain unchanged.

- [ ] Read the cached Sequoia2.4.1 streaming-verifier contract, including when signature checks occur and which validity/revocation checks GoodChecksum covers.
- [ ] Add and run failing behavioral tests for valid content, tampering, foreign/empty trust, malformed/truncated input, weak/future/expired signatures, revoked keys, canonicalization and bounds.
- [ ] Implement the smallest streaming verifier using the existing trusted certificates/policy. Keep errors typed and return plaintext only after verified EOF.
- [ ] Run the focused PGP tests and existing detached verification tests; retain actual RED/GREEN receipts.

### Task 3: Authenticate the Node download boundary

**Files:** Modify src/runtimes/node.rs and existing HTTPS checksum tests; update relevant runtime-security documentation and key provenance.

**Interfaces:** NodeManager::fetch_checksum keeps its current signature but fetches SHASUMS256.txt.asc and returns a digest only after signature verification. No-pgp builds return a clear unsupported-authentication error.

- [ ] Add a failing HTTPS test proving tampered/unknown signatures prevent archive requests and candidate publication/execution. Update existing retry/deadline tests to signed fixtures while retaining their assertions.
- [ ] Load only reviewed embedded certificates with the existing fingerprint-allowlisted loader, verify bounded cleartext, and bind the exact filename before returning its SHA256.
- [ ] Test missing/invalid signatures, valid signed data, incorrect filename, retries, body/deadline limits and feature-disabled behavior. Inject a controlled verification bypass and prove the rejection test turns RED; restore intact source and prove GREEN.
- [ ] Run adjacent Node/PGP tests, all-target Arch Clippy, formatting and source-package checks within a fresh storage budget. Review the full trust/code diff before publishing. Keep broader native, coverage, security-review and release acceptance open until proved.
