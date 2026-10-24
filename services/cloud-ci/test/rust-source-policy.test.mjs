import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { assertRustSourceChange } from "../../../scripts/rust-source-policy.mjs";

const read = (path) => readFileSync(new URL(`../../../${path}`, import.meta.url), "utf8");
const explicitPath = "src/cli/packages/explicit.rs";
const cleanPath = "src/cli/packages/clean.rs";
const explicitSource = read(explicitPath);
const cleanSource = read(cleanPath);

const editExplicit = (source) =>
    source.replace(
        "    packages.sort();",
        `    // audited production edit
    packages.sort();`,
    );
const editClean = (source) =>
    source.replace(
        "    let distro = detect_distro();",
        `    // audited production edit
    let distro = detect_distro();`,
    );

test("pinned explicit.rs allows a production edit after the helper cfg", () => {
    const updated = editExplicit(explicitSource);
    assert.notEqual(updated, explicitSource);
    assert.doesNotThrow(() => assertRustSourceChange(explicitPath, explicitSource, updated));
});

test("pinned clean.rs allows a production edit after the helper cfg", () => {
    const updated = editClean(cleanSource);
    assert.notEqual(updated, cleanSource);
    assert.doesNotThrow(() => assertRustSourceChange(cleanPath, cleanSource, updated));
});

test("pinned explicit.rs rejects test-body mutation", () => {
    const updated = explicitSource.replace('"got: {error}"', '"got: {error} mutated"');
    assert.notEqual(updated, explicitSource);
    assert.throws(
        () => assertRustSourceChange(explicitPath, explicitSource, updated),
        /Automatic repairs cannot change existing Rust tests/,
    );
});

test("pinned clean.rs rejects test-body mutation", () => {
    const updated = cleanSource.replace(
        "assert!(apt_cleanup_requests_unsupported_work(false, false, true));",
        "assert!(!apt_cleanup_requests_unsupported_work(false, false, true));",
    );
    assert.notEqual(updated, cleanSource);
    assert.throws(
        () => assertRustSourceChange(cleanPath, cleanSource, updated),
        /Automatic repairs cannot change existing Rust tests/,
    );
});

test("pinned explicit.rs rejects lint attribute changes", () => {
    const updated = explicitSource.replace(
        '#[allow(clippy::unused_async, reason = "preserves the async command interface")]',
        "#[allow(clippy::unused_async)]",
    );
    assert.notEqual(updated, explicitSource);
    assert.throws(
        () => assertRustSourceChange(explicitPath, explicitSource, updated),
        /Rust conditional attributes and lint policy must remain unchanged/,
    );
});

test("pinned clean.rs rejects reviewed helper cfg changes", () => {
    const updated = cleanSource.replace(
        '#[cfg(any(test, feature = "debian"))]',
        '#[cfg(any(test, feature = "debian", feature = "extra"))]',
    );
    assert.notEqual(updated, cleanSource);
    assert.throws(
        () => assertRustSourceChange(cleanPath, cleanSource, updated),
        /Rust conditional attributes and lint policy must remain unchanged/,
    );
});

test("stacked cfg variant fails closed", () => {
    const stacked = cleanSource.replace(
        `#[cfg(any(test, feature = "debian"))]
fn apt_cleanup_requests_unsupported_work`,
        `#[cfg(feature = "extra")]
#[cfg(any(test, feature = "debian"))]
fn apt_cleanup_requests_unsupported_work`,
    );
    assert.notEqual(stacked, cleanSource);
    assert.throws(
        () => assertRustSourceChange(cleanPath, stacked, editClean(stacked)),
        /Automatic repairs cannot change existing Rust tests/,
    );
});

test("nested cfg variant fails closed", () => {
    const nested = explicitSource.replace(
        `#[cfg(any(
    not(any(feature = "arch", feature = "debian", feature = "debian-pure")),
    test
))]`,
        `#[cfg(any(
    not(any(feature = "arch", feature = "debian", feature = "debian-pure")),
    all(test)
))]`,
    );
    assert.notEqual(nested, explicitSource);
    assert.throws(
        () => assertRustSourceChange(explicitPath, nested, editExplicit(nested)),
        /Automatic repairs cannot change existing Rust tests/,
    );
});

test("raw cfg variant fails closed", () => {
    const raw = cleanSource.replace(
        '#[cfg(any(test, feature = "debian"))]',
        '#[cfg(any(test, feature = r#"debian"#))]',
    );
    assert.notEqual(raw, cleanSource);
    assert.throws(
        () => assertRustSourceChange(cleanPath, raw, editClean(raw)),
        /Automatic repairs cannot change existing Rust tests/,
    );
});

test("drifted snapshot fails closed without refreshing the pin", () => {
    const drifted = explicitSource.replace(
        "//! Explicit package listing functionality",
        "//! Explicit package listing functionality (drifted)",
    );
    assert.notEqual(drifted, explicitSource);
    assert.throws(
        () => assertRustSourceChange(explicitPath, drifted, editExplicit(drifted)),
        /Automatic repairs cannot change existing Rust tests/,
    );
});
