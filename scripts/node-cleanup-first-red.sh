#!/usr/bin/env bash
set -euo pipefail
proof="$RUNNER_TEMP/node-cleanup-first-red"
mkdir "$proof"
node_source="$GITHUB_WORKSPACE/src/runtimes/node.rs"
node_sha=ba492a2f64e6c4b5babbb425751f44c5ae27fb6479225e75fc92c69e58441796
supervisor="$GITHUB_WORKSPACE/scripts/node-cleanup-proof-supervisor.py"
cargo_provider=$(command -v cargo)
rustc_provider=$(command -v rustc)
printf '%s\n' "$GITHUB_SHA" > "$proof/workflow-executed-sha"
git rev-parse HEAD HEAD^{tree} HEAD^ > "$proof/git-identity"
git status --porcelain=v1 > "$proof/git-status"
uname -a > "$proof/uname"
sw_vers > "$proof/sw-vers"
python3 "$supervisor" --out "$proof/rustc" --source "$node_source" --source-sha256 "$node_sha" --deadline 15 --expected-exit 0 -- "$rustc_provider" -vV
python3 "$supervisor" --out "$proof/cargo" --source "$node_source" --source-sha256 "$node_sha" --deadline 15 --expected-exit 0 -- "$cargo_provider" --version
python3 "$supervisor" --out "$proof/build" --source "$node_source" --source-sha256 "$node_sha" --deadline 600 --expected-exit 0 -- "$cargo_provider" test --lib --no-default-features --features macos,pgp,license --locked --profile test --no-run --message-format=json-render-diagnostics
python3 - "$proof" "$GITHUB_WORKSPACE" <<'PYARTIFACT'
import json, pathlib, sys
out, root = map(pathlib.Path, sys.argv[1:])
rows = [json.loads(line) for line in (out/'build/stdout').read_text().splitlines() if line.startswith('{')]
artifacts = [r for r in rows if r.get('reason') == 'compiler-artifact' and r.get('executable') and r.get('profile', {}).get('test') is True and r.get('target', {}).get('kind') == ['lib'] and pathlib.Path(r['target']['src_path']).resolve() == (root/'src/lib.rs').resolve()]
assert len(artifacts) == 1, artifacts
artifact = artifacts[0]
assert artifact.get('fresh') is False, 'owning library was not freshly compiled'
exe = pathlib.Path(artifact['executable']).resolve(strict=True)
assert exe.is_relative_to((root/'target').resolve())
(out/'owning-library-artifact.json').write_text(json.dumps(artifact, indent=2)+'\n')
(out/'owning-library-path').write_text(str(exe)+'\n')
PYARTIFACT
library=$(cat "$proof/owning-library-path")
selector=runtimes::node::tests::node_cleanup_live_overflow_injected_group_eperm
python3 "$supervisor" --out "$proof/list" --source "$node_source" --source-sha256 "$node_sha" --deadline 15 --expected-exit 0 --require "$selector: test" --require '1 test, 0 benchmarks' -- "$library" --exact "$selector" --list
python3 "$supervisor" --out "$proof/first-intended-red" --source "$node_source" --source-sha256 "$node_sha" --deadline 20 --expected-exit 101 --require "test $selector ... FAILED" --require 'wrong refusal:' --require 'nonterminal member' --require '0 passed; 1 failed; 0 ignored;' --forbid 'HARNESS' --forbid 'EXPECTED_CLEANUP_HOLD' -- "$library" --exact "$selector" --test-threads=1 --color never
printf '%s\n' 'FIRST_INTENDED_RED_CAPTURED_PENDING_ROOT_REVIEW_NO_PRODUCTION_IMPLEMENTATION'
