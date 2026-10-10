#!/usr/bin/env python3
"""Fail when per-file technical-debt counts exceed a shrink-only baseline.

Each ratchet counts occurrences of one debt pattern per file and compares the
result against ``scripts/debt-ratchets/<name>.baseline``. A file without a
baseline entry must have zero findings (new code is born clean); a listed file
may only shrink. ``--refresh`` records decreases after a cleanup and refuses to
raise any count, because a baseline that can grow is not a gate.

Usage:
    python3 scripts/debt-ratchet.py                 # gate (exit 1 on regression)
    python3 scripts/debt-ratchet.py --report        # verbose status for all files
    python3 scripts/debt-ratchet.py --refresh       # lower the floor after cleanup
    python3 scripts/debt-ratchet.py --ci            # verified event-base floor
    python3 scripts/debt-ratchet.py --base-revision <sha>  # exact local ancestor

CI verifies the repository, checkout SHA and exact PR merge parents before
reading the floor from the event base commit. Missing objects or baselines fail
closed; candidate floors cannot increase. Independent checks cannot refresh or
seed floors. This enforces ratchet policy, not a boundary against rewriting the
checker or workflow.

Exit codes: 0 clean, 1 regression or refused refresh, 2 invalid usage,
4 configuration error.
"""
import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASELINE_DIR = Path('scripts') / 'debt-ratchets'

# Directories and generated files that are not part of the maintained surface.
EXCLUDE_PARTS = frozenset({
    '.git', '.pi', '.pytest_cache', '__pycache__', 'node_modules', 'target',
    'vendor',
})
EXCLUDE_FILES = frozenset({'docs/changelog.md'})
ALLOWED_SUFFIXES = frozenset({
    '.bash', '.cfg', '.conf', '.json', '.md', '.py', '.rs', '.sh', '.toml',
    '.tsv', '.txt', '.xml', '.yaml', '.yml', '.zsh',
})
ALLOWED_NAMES = frozenset({'Makefile', 'Dockerfile'})
MAX_FILE_BYTES = 2 * 1024 * 1024
RAW_LITERAL = re.compile(r'(?:br|cr|r)(#*)"')
CHAR_LITERAL = re.compile(r"'(?:[^'\\\n]|\\(?:u\{[0-9a-fA-F_]+\}|x[0-9a-fA-F]{2}|[^\n]))'")
ATTRIBUTE_START = re.compile(r'#\s*!?\s*\[')

def rust_code(text):
    """Mask comments and literals while retaining token boundaries and newlines."""
    masked = list(text)
    index = 0
    while index < len(text):
        end = index
        if text.startswith('//', index):
            end = text.find('\n', index)
            if end == -1:
                end = len(text)
        elif text.startswith('/*', index):
            depth = 1
            end = index + 2
            while end < len(text) and depth:
                if text.startswith('/*', end):
                    depth += 1
                    end += 2
                elif text.startswith('*/', end):
                    depth -= 1
                    end += 2
                else:
                    end += 1
        else:
            raw = RAW_LITERAL.match(text, index) if text[index] in 'bcr' else None
            if raw:
                delimiter = '"' + raw.group(1)
                closing = text.find(delimiter, raw.end())
                end = len(text) if closing == -1 else closing + len(delimiter)
            elif text[index] == '"':
                end = index + 1
                while end < len(text):
                    if text[end] == '\\':
                        end = min(end + 2, len(text))
                    elif text[end] == '"':
                        end += 1
                        break
                    else:
                        end += 1
            elif text[index] == "'":
                # Lifetimes remain code; only a complete character literal is masked.
                char = CHAR_LITERAL.match(text, index)
                if char:
                    end = char.end()
        if end > index:
            masked[index:end] = ['\n' if char == '\n' else ' ' for char in text[index:end]]
            index = end
        else:
            index += 1
    return ''.join(masked)


def meta_arguments(text):
    """Split a Rust metadata list at commas outside nested token groups."""
    depth = 0
    start = 0
    for index, char in enumerate(text):
        if char in '([{':
            depth += 1
        elif char in ')]}':
            depth -= 1
        elif char == ',' and depth == 0:
            yield text[start:index].strip()
            start = index + 1
    yield text[start:].strip()


def count_rust_lint_attributes(text):
    """Count physical core debt lint lists, including conditional attributes.

    Each allow/expect list counts once. Tool lints and expanded macros are
    outside this ratchet; feature predicates do not hide physical annotations.
    """
    code = rust_code(text)
    count = 0
    offset = 0
    while attribute := ATTRIBUTE_START.search(code, offset):
        start = attribute.end()
        end = start
        depth = 1
        while end < len(code) and depth:
            if code[end] == '[':
                depth += 1
            elif code[end] == ']':
                depth -= 1
            end += 1
        if depth:
            break
        pending = [code[start:end - 1].strip()]
        while pending:
            meta = pending.pop()
            match = re.fullmatch(r'(?:r#)?(allow|expect|cfg_attr)\s*\((.*)\)', meta, re.DOTALL)
            if not match:
                continue
            arguments = list(meta_arguments(match.group(2)))
            if match.group(1) == 'cfg_attr':
                pending.extend(arguments[1:])
            elif any(re.fullmatch(r'(?:r#)?(?:dead_code|unused(?:_[a-z0-9_]+)?)', arg)
                     for arg in arguments):
                count += 1
        offset = end
    return count


RATCHETS = {
    'todo-markers': re.compile(r'\b(?:TODO|FIXME|HACK|XXX)\b'),
    'dead-code-allows': count_rust_lint_attributes,
}


def candidate_files(root):
    for path in sorted(root.rglob('*')):
        if not path.is_file() or path.is_symlink():
            continue
        relative = path.relative_to(root)
        if EXCLUDE_PARTS & set(relative.parts):
            continue
        if relative.as_posix() in EXCLUDE_FILES:
            continue
        if path.suffix not in ALLOWED_SUFFIXES and path.name not in ALLOWED_NAMES:
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        yield relative


def count_matches(root, pattern):
    counts = {}
    for relative in candidate_files(root):
        if pattern is count_rust_lint_attributes and relative.suffix != '.rs':
            continue
        try:
            text = (root / relative).read_text(encoding='utf-8')
        except (OSError, UnicodeDecodeError):
            continue
        found = pattern(text) if callable(pattern) else len(pattern.findall(text))
        if found:
            counts[relative.as_posix()] = found
    return counts


def baseline_path(baseline_dir, name):
    return baseline_dir / f'{name}.baseline'


def parse_baseline(text, label):
    entries = {}
    for number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        match = re.fullmatch(r'(\d+) = (.+)', line)
        if not match or match.group(2) in entries:
            raise ValueError(f'{label}:{number}: invalid or duplicate baseline row')
        entries[match.group(2)] = int(match.group(1))
    return entries


def read_baseline(path):
    if not path.exists():
        return None
    try:
        return parse_baseline(path.read_text(encoding='utf-8'), path)
    except (OSError, ValueError) as error:
        print(f'configuration error: {error}', file=sys.stderr)
        raise SystemExit(4) from error


def git_output(root, *arguments, raw=False):
    output = subprocess.run(['git', '-C', str(root), *arguments], check=True,
                            capture_output=True, text=True, encoding='utf-8', timeout=60,
                            env=dict(os.environ, GIT_NO_REPLACE_OBJECTS='1')).stdout
    return output if raw else output.strip()


def commit_identity(value):
    if not isinstance(value, str) or not re.fullmatch(r'[0-9a-f]{40}', value) or value == '0' * 40:
        raise ValueError('missing or invalid debt base commit identity')
    return value


def ci_base_revision(root):
    head = commit_identity(os.environ.get('GITHUB_SHA'))
    if Path(git_output(root, 'rev-parse', '--show-toplevel')).resolve() != root:
        raise ValueError('CI root is not the checkout root')
    if git_output(root, 'rev-parse', 'HEAD') != head:
        raise ValueError('CI checkout does not match GITHUB_SHA')
    event = json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text(encoding='utf-8'))
    if not isinstance(event, dict):
        raise ValueError('invalid GitHub event payload')
    repository = os.environ['GITHUB_REPOSITORY']
    if not repository or event['repository']['full_name'] != repository:
        raise ValueError('CI event repository mismatch')
    kind = os.environ['GITHUB_EVENT_NAME']
    if kind == 'pull_request':
        pr = event['pull_request']
        if pr['base']['repo']['full_name'] != repository:
            raise ValueError('PR base repository mismatch')
        source = commit_identity(pr['head']['sha'])
        base = commit_identity(pr['base']['sha'])
        parents = git_output(root, 'show', '-s', '--format=%P', head).split()
        if parents != [base, source]:
            raise ValueError(
                'PR merge parents do not match event base/head: '
                f'event base/head={base} {source}; '
                f'actual parents={" ".join(parents)}; checkout={head}')
        return base
    if kind == 'push':
        if event.get('after') != head:
            raise ValueError('push event does not match CI checkout')
        return commit_identity(event.get('before'))
    if kind == 'merge_group':
        group = event.get('merge_group')
        if not isinstance(group, dict) or group.get('head_sha') != head:
            raise ValueError('merge group does not match CI checkout')
        return commit_identity(group.get('base_sha'))
    if kind == 'workflow_dispatch':
        # A manual run verifies the selected commit against its first parent.
        return commit_identity(git_output(root, 'rev-parse', head + '^'))
    raise ValueError('unsupported debt CI event: ' + kind)


def independent_baselines(root, baseline_dir, revision):
    revision = commit_identity(revision)
    if git_output(root, 'rev-parse', revision + '^{commit}') != revision:
        raise ValueError('debt base does not identify a commit')
    if revision == git_output(root, 'rev-parse', 'HEAD'):
        raise ValueError('debt base must precede the candidate commit')
    git_output(root, 'merge-base', '--is-ancestor', revision, 'HEAD')
    relative = baseline_dir.relative_to(root)
    floors = {}
    for name in RATCHETS:
        path = (relative / f'{name}.baseline').as_posix()
        text = git_output(root, 'show', revision + ':' + path, raw=True)
        if len(text.encode('utf-8')) > MAX_FILE_BYTES:
            raise ValueError('oversized debt base baseline: ' + path)
        floors[name] = parse_baseline(text, revision + ':' + path)
    print('Verified debt base: ' + revision)
    return floors


def render_baseline(counts):
    rows = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    return ''.join(f'{count} = {path}\n' for path, count in rows)


def evaluate(counts, baseline):
    regressions = []
    for path, count in sorted(counts.items()):
        previous = baseline.get(path)
        if previous is None or count > previous:
            regressions.append((path, count, previous))
    fixed = sorted(
        (path, previous, counts.get(path, 0))
        for path, previous in baseline.items()
        if counts.get(path, 0) < previous
    )
    return regressions, fixed


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--baseline-dir', type=Path, default=None)
    parser.add_argument('--refresh', action='store_true')
    parser.add_argument('--report', action='store_true')
    base = parser.add_mutually_exclusive_group()
    base.add_argument('--base-revision', help='exact ancestor commit supplying the independent floor')
    base.add_argument('--ci', action='store_true', help='bind the floor to the GitHub event base')
    args = parser.parse_args(argv)
    if args.refresh and (args.ci or args.base_revision):
        parser.error('independent base checks cannot seed or refresh baselines')
    if args.ci and args.baseline_dir is not None:
        parser.error('CI uses the canonical baseline directory')

    root = args.root.resolve()
    baseline_dir = (args.baseline_dir or root / BASELINE_DIR).resolve()
    if not root.is_dir():
        print(f'configuration error: {root} is not a directory', file=sys.stderr)
        return 4

    floors = None
    if args.ci or args.base_revision:
        try:
            if args.ci and baseline_dir != root / BASELINE_DIR:
                raise ValueError('CI baseline directory must be canonical, not a symlink')
            revision = ci_base_revision(root) if args.ci else args.base_revision
            floors = independent_baselines(root, baseline_dir, revision)
            for name in RATCHETS:
                path = baseline_path(baseline_dir, name)
                if not path.is_file() or path.is_symlink() or path.stat().st_size > MAX_FILE_BYTES:
                    raise ValueError('missing or invalid candidate baseline: ' + str(path))
        except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
            print(f'configuration error: cannot verify independent debt floor: {error}', file=sys.stderr)
            return 4

    failures = []
    summaries = []
    for name, pattern in RATCHETS.items():
        counts = count_matches(root, pattern)
        path = baseline_path(baseline_dir, name)
        baseline = read_baseline(path)
        seeding = baseline is None
        baseline = baseline or {}
        raised = []
        if floors is not None:
            # An explicit zero row retains the implicit zero floor.
            raised = [row for row in evaluate(baseline, floors[name])[0] if row[1]]
            for offender, count, previous in raised:
                failures.append(f'{name}: candidate baseline increased: {offender} = {count}'
                                + (f' (base {previous})' if previous is not None else ' (unlisted in base)'))
            for offender, count, previous in evaluate(counts, floors[name])[0]:
                failures.append(f'{name}: debt exceeds independent base: {offender} = {count}'
                                + (f' (base {previous})' if previous is not None else ' (unlisted in base)'))
        regressions, fixed = evaluate(counts, baseline)

        for offender, previous, count in fixed:
            print(f'{name}: improved: {offender} {previous} -> {count}')
        if args.refresh:
            if seeding:
                baseline_dir.mkdir(parents=True, exist_ok=True)
                path.write_text(render_baseline(counts), encoding='utf-8')
                summaries.append(
                    f'{name}: seeded ({len(counts)} files, {sum(counts.values())} findings)'
                )
                continue
            if regressions:
                for offender, count, previous in regressions:
                    kind = 'increased' if previous is not None else 'new_files'
                    failures.append(
                        f'{name}: {kind}: {offender} = {count}'
                        + (f' (baseline {previous})' if previous is not None else '')
                    )
                continue
            baseline_dir.mkdir(parents=True, exist_ok=True)
            path.write_text(render_baseline(counts), encoding='utf-8')
            summaries.append(
                f'{name}: refreshed ({len(counts)} files, {sum(counts.values())} findings)'
            )
            continue

        for offender, count, previous in regressions:
            kind = 'new_files' if previous is None else 'increased'
            failures.append(
                f'{name}: {kind}: {offender} = {count}'
                + (f' (baseline {previous})' if previous is not None else '')
            )
        summaries.append(
            f'{name}: {"pass" if not regressions and not raised else "fail"} '
            f'({sum(counts.values())} findings, {len(fixed)} improved)'
        )

    for line in summaries:
        print(f'ratchet {line}')
    if failures:
        print('debt ratchet failed; fix the debt or lower the baseline with --refresh:',
              file=sys.stderr)
        for line in failures:
            print(f'  {line}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
