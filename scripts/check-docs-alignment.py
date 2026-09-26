#!/usr/bin/env python3
"""Fail when documentation promises a command surface the parser does not have.

The command definitions in ``src/cli/args.rs`` are the source of truth. A doc line
that invokes ``omg <command> ...`` is resolved against those definitions, including
nested subcommands and aliases. Options are checked against the resolved command
plus the global options.

Environment variables mentioned in docs must exist somewhere in the repository
(``src/``, ``scripts/``, ``.github/``, ``install.sh``, ``Makefile``); the installer
and CI own several of them.

Generated and internal files are skipped: ``docs/changelog.md`` (generated from
commits) and ``.superpowers/**``.

Exit status is 0 only when every reference resolves. Findings print one per line so
they can be read in a CI log.
"""
import argparse
import re
import sys
from pathlib import Path

GLOBAL_OPTIONS = frozenset({
    'v', 'verbose', 'q', 'quiet', 'json', 'all-commands', 'h', 'help', 'V', 'version',
})

# Words that look like commands but are documented *as removed*. Keep this list
# short and explain each entry; it is not a place to hide a broken reference.
DOCUMENTED_REMOVALS = frozenset({'license'})

SKIP_PARTS = frozenset({'.superpowers'})
SKIP_FILES = frozenset({'changelog.md'})

ENV_ROOTS = ('src', 'scripts', '.github', 'tests', 'benches', 'fuzz')
ENV_FILES = ('install.sh', 'Makefile', 'Cargo.toml', 'SECURITY.md', 'CONTRIBUTING.md')


def kebab(name):
    """Convert a Rust variant name to the kebab-case spelling clap exposes."""
    dashed = re.sub(r'([a-z0-9])([A-Z])', r'\1-\2', name)
    dashed = re.sub(r'([A-Z]+)([A-Z][a-z])', r'\1-\2', dashed)
    return dashed.lower()


class Variant:
    """One command or subcommand: its options and the subcommand enum it owns."""

    def __init__(self, name, key, options, aliases, sub_enum):
        self.name = name
        self.key = key
        self.options = options
        self.aliases = aliases
        self.sub_enum = sub_enum


def parse_enums(lines):
    """Return {enum name: {kebab command: Variant}} parsed from args.rs."""
    enums = {}
    index, count = 0, len(lines)
    while index < count:
        head = re.match(r'^pub enum (\w+)\s*\{', lines[index])
        if not head:
            index += 1
            continue
        variants = {}
        cursor = index + 1
        while cursor < count and not lines[cursor].startswith('}'):
            variant = re.match(r'^    ([A-Z]\w*)\s*([{,(]|$)', lines[cursor])
            if not variant:
                cursor += 1
                continue
            key = kebab(variant.group(1))
            options, aliases, sub_enum, body = {}, [], None, []
            if variant.group(2) == '{':
                scan = cursor + 1
                while (scan < count
                       and not re.match(r'^    \},?\s*$', lines[scan])
                       and not re.match(r'^    [A-Z]\w*\s*(\{|,|\(|$)', lines[scan])):
                    body.append(lines[scan])
                    scan += 1
            body_text = '\n'.join(body)
            context = []
            above = cursor - 1
            while above >= 0 and re.match(r'^\s*(///|#\[command)', lines[above]):
                context.insert(0, lines[above])
                above -= 1
            context_text = '\n'.join(context)
            aliases += re.findall(r'visible_alias\s*=\s*"([^"]+)"', context_text)
            for group in re.findall(r'aliases\s*=\s*\[([^\]]+)\]', context_text):
                aliases += re.findall(r'"([^"]+)"', group)
            explicit = (re.search(r'command\(name\s*=\s*"([^"]+)"', context_text)
                        or re.search(r'command\(name\s*=\s*"([^"]+)"', body_text))
            if explicit:
                key = explicit.group(1)
            nested = re.search(r'command:\s*(?:Option<)?(\w+Commands)\b', body_text)
            if nested:
                sub_enum = nested.group(1)
            for offset, line in enumerate(body):
                if '#[arg(' not in line:
                    continue
                field_at = offset + 1
                while field_at < len(body) and not re.match(r'^\s*(pub )?[a-z_]+:', body[field_at]):
                    field_at += 1
                if field_at >= len(body):
                    continue
                field = re.match(r'^\s*(?:pub )?([a-z_]+):', body[field_at])
                if not field:
                    continue
                name = field.group(1).replace('_', '-')
                long_form = re.search(r'long\s*=\s*"([^"]+)"', line)
                if long_form:
                    name = long_form.group(1)
                elif not re.search(r'(^|[\s,(])long([\s,)=]|$)', line):
                    name = None
                if name:
                    options[name] = True
                short_form = re.search(r"short\s*=\s*'([^']+)'", line)
                if short_form:
                    options[short_form.group(1)] = True
                elif re.search(r'(^|[\s,(])short([\s,)=]|$)', line):
                    options[field.group(1)[0]] = True
            variants[key] = Variant(variant.group(1), key, options, aliases, sub_enum)
            cursor += 1
        enums[head.group(1)] = variants
        index = cursor
    return enums



def doc_files(repo):
    """Every markdown file whose command references must resolve."""
    files = [path for path in (repo / 'docs').rglob('*.md')
             if not SKIP_PARTS.intersection(path.parts) and path.name not in SKIP_FILES]
    for extra in ('README.md', 'CONTRIBUTING.md', 'SECURITY.md', 'FEDORA-ENGINE.md',
                  'GATE-TEST.md'):
        candidate = repo / extra
        if candidate.exists():
            files.append(candidate)
    return sorted(files)


def tokens_for(line):
    """Split an ``omg ...`` doc line into words and options.

    Everything after a bare ``--`` belongs to the wrapped tool, so it is ignored,
    and a trailing ``#`` starts a shell comment rather than another argument. A
    word that starts with a placeholder (``<PACKAGE>``) or contains shell syntax
    ends the command path.
    """
    body = re.sub(r'^(#\s*)?(\$\s*)?', '', line.strip())
    parts = body.split()
    if len(parts) < 2:
        return [], []
    words, options, passthrough = [], [], False
    for token in parts[1:]:
        if token == '--':
            passthrough = True
            continue
        if passthrough:
            continue
        if token.startswith('#') and len(token) == 1:
            break
        if token.startswith('-'):
            options.append(token)
            continue
        if (re.match(r'^[A-Z]', token) or token.startswith('<')
                or any(char in token for char in '|=<>()[]')):
            break
        words.append(token)
    return words, options


def resolve(enums, words):
    """Walk the parsed enums along a command path. Returns (variant, bad word)."""
    current = enums.get('Commands', {})
    owner = None
    for word in words:
        if current is None:
            return owner, None
        key = word if word in current else next(
            (name for name, variant in current.items() if word in variant.aliases), None)
        if key is None:
            return owner, word
        owner = current[key]
        current = enums.get(owner.sub_enum) if owner.sub_enum else None
    return owner, None



def scan_docs(repo, enums):
    """Return findings for command paths and options that do not resolve."""
    findings = []
    scanned = 0
    for path in doc_files(repo):
        relative = path.relative_to(repo).as_posix()
        for number, line in enumerate(path.read_text(encoding='utf-8').splitlines(), 1):
            if not re.match(r'^(#\s*)?(\$\s*)?omg(\s|$)', line.strip()):
                continue
            words, options = tokens_for(line)
            if not words:
                continue
            scanned += 1
            if words[0] in DOCUMENTED_REMOVALS:
                continue
            owner, bad = resolve(enums, words)
            if bad:
                findings.append(f'{relative}:{number}: unknown command word {bad!r} '
                                f'in "omg {" ".join(words)}"')
                continue
            if owner is None:
                continue
            for option in options:
                name = option.lstrip('-')
                if name in GLOBAL_OPTIONS or name in owner.options:
                    continue
                known = any(name in variant.options
                            for variants in enums.values() for variant in variants.values())
                reason = 'not accepted by' if known else 'unknown'
                findings.append(f'{relative}:{number}: option --{name} {reason} '
                                f'"omg {" ".join(words)}"')
    return findings, scanned


def repo_environment_variables(repo):
    """Every OMG_* name that exists anywhere in the repository."""
    found = set()
    for root in ENV_ROOTS:
        directory = repo / root
        if not directory.is_dir():
            continue
        for path in directory.rglob('*'):
            if not path.is_file() or path.stat().st_size > 4 * 1024 * 1024:
                continue
            found.update(re.findall(r'OMG_[A-Z0-9_]{2,}',
                                    path.read_text(encoding='utf-8', errors='ignore')))
    for name in ENV_FILES:
        path = repo / name
        if path.is_file():
            found.update(re.findall(r'OMG_[A-Z0-9_]{2,}',
                                    path.read_text(encoding='utf-8', errors='ignore')))
    return found


def scan_environment(repo):
    """Return documented environment variables that exist nowhere in the repo."""
    known = repo_environment_variables(repo)
    findings = set()
    for path in doc_files(repo):
        relative = path.relative_to(repo).as_posix()
        for number, line in enumerate(path.read_text(encoding='utf-8').splitlines(), 1):
            for name in re.findall(r'OMG_[A-Z0-9_]{2,}', line):
                if name not in known:
                    findings.add(f'{relative}:{number}: unknown environment variable {name}')
    return sorted(findings)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('repo', nargs='?', default='.', help='repository root')
    parser.add_argument('--skip-environment', action='store_true',
                        help='only check command paths and options')
    arguments = parser.parse_args(argv)
    repo = Path(arguments.repo).resolve()
    args_rs = repo / 'src' / 'cli' / 'args.rs'
    if not args_rs.is_file():
        print(f'error: {args_rs} not found; pass the repository root', file=sys.stderr)
        return 2
    enums = parse_enums(args_rs.read_text(encoding='utf-8').splitlines())
    if 'Commands' not in enums:
        print('error: could not parse the Commands enum in args.rs', file=sys.stderr)
        return 2

    findings, scanned = scan_docs(repo, enums)
    if not arguments.skip_environment:
        findings += scan_environment(repo)

    if findings:
        print(f'docs alignment: {len(findings)} problem(s) in {scanned} command references')
        for finding in findings:
            print(finding)
        return 1
    print(f'docs alignment: ok ({scanned} command references checked)')
    return 0


if __name__ == '__main__':
    sys.exit(main())
