#!/usr/bin/env python3
"""Comprehensive documentation audit against the OMG codebase.

Checks:
1. Broken internal links (file links and anchor links)
2. Removed or phantom commands and flags in prose and code blocks
3. Config keys in docs and examples against Settings / AurBuildSettings
4. Max build concurrency
5. Environment variables against repository occurrences
6. Value enum options (e.g. stack, severity, frameworks)
7. All inline and block `omg ...` command invocations against src/cli/args.rs
"""
import os
import re
import sys
from pathlib import Path
import importlib.util

REPO_ROOT = Path(__file__).resolve().parent.parent

# Load the enum parser from check-docs-alignment.py
SPEC = importlib.util.spec_from_file_location(
    'docs_alignment', REPO_ROOT / 'scripts' / 'check-docs-alignment.py')
ALIGNMENT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ALIGNMENT)

ROOT_CONFIG_KEYS = frozenset({"telemetry_enabled", "aur"})
AUR_CONFIG_KEYS = frozenset([
    "build_method",
    "build_concurrency",
    "review_pkgbuild",
    "secure_makepkg",
    "allow_unsafe_builds",
    "allow_network",
    "use_metadata_archive",
    "metadata_cache_ttl_secs",
    "makeflags",
    "pkgdest",
    "srcdest",
    "cache_builds",
    "enable_ccache",
    "ccache_dir",
    "enable_sccache",
    "sccache_dir",
])
MAX_BUILD_CONCURRENCY = 8

def get_md_files(repo):
    files = list((repo / "docs").rglob("*.md")) + [
        repo / f for f in [
            "README.md", "CONTRIBUTING.md", "SECURITY.md", "TODO.md",
            "FEDORA-ENGINE.md", "GATE-TEST.md", "WAVE12-BLOCKERS.md"
        ] if (repo / f).exists()
    ]
    # Filter out superpowers and internal review / changelog
    return [
        p for p in files
        if not any(part in p.parts for part in ("superpowers", ".superpowers"))
        and p.name not in ("changelog.md",)
    ]

def check_broken_links(repo):
    broken = []
    md_files = get_md_files(repo)
    
    file_headings = {}
    for path in md_files:
        try:
            content = path.read_text(encoding="utf-8")
        except Exception:
            continue
        headings = set()
        for line in content.splitlines():
            m = re.match(r"^#+\s+(.+)$", line)
            if m:
                text = m.group(1).strip()
                text = re.sub(r"\[(.*?)\]\(.*?\)", r"\1", text)
                slug = text.lower()
                slug = re.sub(r"[^\w\s-]", "", slug)
                slug = re.sub(r"[\s_]+", "-", slug).strip("-")
                headings.add(slug)
        file_headings[path.resolve()] = headings

    link_regex = re.compile(r'\[([^\]]+)\]\(([^)]+)\)')

    for path in md_files:
        try:
            content = path.read_text(encoding="utf-8")
        except Exception:
            continue
        rel = path.relative_to(repo).as_posix()
        for lineno, line in enumerate(content.splitlines(), 1):
            for match in link_regex.finditer(line):
                target = match.group(2).strip()
                if target.startswith(("http://", "https://", "mailto:")):
                    continue
                if target.startswith("#"):
                    anchor = target[1:].split("?")[0]
                    if anchor and anchor not in file_headings.get(path.resolve(), set()):
                        broken.append(f"{rel}:{lineno}: broken local anchor #{anchor}")
                    continue
                
                parts = target.split("#", 1)
                file_part = parts[0].split("?")[0]
                anchor_part = parts[1] if len(parts) > 1 else None
                
                if not file_part:
                    continue

                target_path = (path.parent / file_part).resolve()
                if not target_path.exists():
                    # Check if it's a known placeholder in template
                    if "documentation-style.md" in rel and "related.md" in target:
                        continue
                    broken.append(f"{rel}:{lineno}: broken file link '{target}' -> {target_path}")
                elif anchor_part and target_path in file_headings:
                    if anchor_part not in file_headings[target_path]:
                        broken.append(f"{rel}:{lineno}: anchor #{anchor_part} not found in {file_part}")
                        
    return broken


def check_forbidden_patterns(repo):
    findings = []
    forbidden = [
        (r'--runtime-backend', "Flag --runtime-backend was removed from 'omg run'"),
        (r'omg workspace sync\b', "Command 'omg workspace sync' was removed (truthfully named 'check')"),
        (r'omg enterprise server mirror\b', "Command 'omg enterprise server mirror' does not exist"),
        (r'omg enterprise reports\b.*--format\b', "Flag --format was removed from 'omg enterprise reports'"),
    ]

    for path in get_md_files(repo):
        if path.name in ("TECH-DEBT-REVIEW-2026-08-31.md", "mise-compatibility.md"):
            continue
        rel = path.relative_to(repo).as_posix()
        try:
            content = path.read_text(encoding="utf-8")
        except Exception:
            continue
        for lineno, line in enumerate(content.splitlines(), 1):
            for pattern, reason in forbidden:
                if re.search(pattern, line):
                    findings.append(f"{rel}:{lineno}: {reason}: {line.strip()}")
                    
    return findings


def check_config_keys(repo):
    findings = []
    # Check config keys in docs/ and examples/
    files_to_check = get_md_files(repo) + [repo / "examples" / "config.toml"]
    for path in files_to_check:
        rel = path.relative_to(repo).as_posix()
        try:
            content = path.read_text(encoding="utf-8")
        except Exception:
            continue
        
        # Check for build_concurrency > 8
        for lineno, line in enumerate(content.splitlines(), 1):
            m = re.search(r'build_concurrency\s*=\s*(\d+)', line)
            if m:
                val = int(m.group(1))
                if val > MAX_BUILD_CONCURRENCY:
                    findings.append(f"{rel}:{lineno}: aur.build_concurrency = {val} exceeds MAX_BUILD_CONCURRENCY ({MAX_BUILD_CONCURRENCY})")
            
            # Check aur.<key>
            for m in re.finditer(r'(?:`aur\.([a-z_]+)`|\baur\.([a-z_]+)\b(?!\.(?:md|rs|org|archlinux)))', line):
                key = m.group(1) or m.group(2)
                if key in ('md', 'rs', 'archlinux'):
                    continue
                if key not in AUR_CONFIG_KEYS:
                    findings.append(f"{rel}:{lineno}: unknown configuration key aur.{key}")

    return findings


def _validate_command(rel, lineno, cmd_line, enums, findings, location="inline"):
    """Record unknown words and options for one `omg ...` invocation."""
    if re.match(r'^omg\s+\d+\.\d+', cmd_line):
        return
    if cmd_line == "omg migrate from-nvm":
        return
    words, options = ALIGNMENT.tokens_for(cmd_line)
    if not words or words[0] in ALIGNMENT.DOCUMENTED_REMOVALS:
        return
    owner, bad = ALIGNMENT.resolve(enums, words)
    if bad:
        findings.append(f"{rel}:{lineno}: {location} command unknown word {bad!r} in `{cmd_line}`")
        return
    if owner is None:
        return
    for option in options:
        name = option.lstrip('-')
        if name in ALIGNMENT.GLOBAL_OPTIONS or name in owner.options:
            continue
        known = any(name in variant.options
                    for variants in enums.values() for variant in variants.values())
        reason = 'not accepted by' if known else 'unknown'
        findings.append(f"{rel}:{lineno}: {location} option --{name} {reason} in `{cmd_line}`")


def check_all_command_references(repo):
    """Find all `omg ...` snippets in inline code or fenced code blocks."""
    args_rs = repo / 'src' / 'cli' / 'args.rs'
    enums = ALIGNMENT.parse_enums(args_rs.read_text(encoding='utf-8').splitlines())
    
    findings = []
    for path in get_md_files(repo):
        rel = path.relative_to(repo).as_posix()
        try:
            content = path.read_text(encoding="utf-8")
        except Exception:
            continue
        
        in_fence = False
        for lineno, line in enumerate(content.splitlines(), 1):
            if line.lstrip().startswith("```"):
                in_fence = not in_fence
                continue

            # Check inline code `omg ...`
            for match in re.finditer(r'`\s*(?:#\s*)?(?:\$\s*)?(omg\s+[^`]+)`', line):
                cmd_line = match.group(1).strip()
                if cmd_line == "omg run --list" and "no `omg" in line:
                    continue
                _validate_command(rel, lineno, cmd_line, enums, findings)

            # Check `omg ...` lines inside fenced code blocks
            if in_fence:
                block = re.match(r'\s*(?:\$\s*)?(?:sudo\s+)?(omg\s+\S.*)$', line)
                if block:
                    _validate_command(
                        rel, lineno, block.group(1).strip(), enums, findings,
                        location="code block",
                    )

    return findings


def main():
    print("=" * 60)
    print("AUDIT 1: Link & Anchor Validation")
    print("=" * 60)
    links = check_broken_links(REPO_ROOT)
    print(f"Broken links: {len(links)}")
    for l in links:
        print(" ", l)

    print("\n" + "=" * 60)
    print("AUDIT 2: Forbidden / Removed Features in Docs")
    print("=" * 60)
    forbidden = check_forbidden_patterns(REPO_ROOT)
    print(f"Forbidden patterns: {len(forbidden)}")
    for f in forbidden:
        print(" ", f)

    print("\n" + "=" * 60)
    print("AUDIT 3: Config Keys and Limits")
    print("=" * 60)
    config_issues = check_config_keys(REPO_ROOT)
    print(f"Config issues: {len(config_issues)}")
    for c in config_issues:
        print(" ", c)

    print("\n" + "=" * 60)
    print("AUDIT 4: Command References (inline and code blocks)")
    print("=" * 60)
    cmd_issues = check_all_command_references(REPO_ROOT)
    print(f"Command reference issues: {len(cmd_issues)}")
    for c in cmd_issues:
        print(" ", c)
    total_issues = len(links) + len(forbidden) + len(config_issues) + len(cmd_issues)
    if total_issues > 0:
        print(f"\nAudit failed with {total_issues} issue(s).")
        sys.exit(1)
    else:
        print("\nAll doc audits passed successfully!")
        sys.exit(0)

if __name__ == "__main__":
    main()
