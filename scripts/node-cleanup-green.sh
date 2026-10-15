#!/usr/bin/env bash
set -euo pipefail
proof="$RUNNER_TEMP/node-cleanup-green"
mkdir "$proof"
node_source="$GITHUB_WORKSPACE/src/runtimes/node.rs"
node_sha=273699782d712910ac5942d1abc65d996d958d2c9e31dfc362b5615a34582719
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
selectors=(
  runtimes::node::tests::node_cleanup_live_overflow_injected_group_eperm
  runtimes::node::tests::node_cleanup_already_terminal_skips_direct_signal
  runtimes::node::tests::node_cleanup_racing_exit_esrch_retains_overflow
  runtimes::node::tests::node_cleanup_racing_exit_eio_remains_failure
  runtimes::node::tests::terminal_group_tests::terminal_group_error_census_records_first_nonterminal_leader
  runtimes::node::tests::terminal_group_tests::terminal_group_error_census_records_second_nonterminal_other
  runtimes::node::tests::terminal_group_tests::terminal_group_error_census_bounds_both_refused_snapshots
  runtimes::node::tests::terminal_group_tests::terminal_group_accepts_complete_stable_owned_zombies
  runtimes::node::tests::terminal_group_tests::terminal_group_refuses_failed_capture_and_wrong_owned_identity
  runtimes::node::tests::terminal_group_tests::terminal_group_refuses_incomplete_api_responses_and_mismatched_rows
  runtimes::node::tests::terminal_group_tests::terminal_group_refuses_missing_duplicate_live_foreign_and_malformed_members
  runtimes::node::tests::terminal_group_tests::terminal_group_refuses_membership_or_identity_churn
)
index=0
for selector in "${selectors[@]}"; do
  index=$((index + 1))
  python3 "$supervisor" --out "$proof/list-$index" --source "$node_source" --source-sha256 "$node_sha" --deadline 15 --expected-exit 0 --require "$selector: test" --require '1 test, 0 benchmarks' -- "$library" --exact "$selector" --list
  python3 "$supervisor" --out "$proof/body-$index" --source "$node_source" --source-sha256 "$node_sha" --deadline 20 --expected-exit 0 --require "test $selector ... ok" --require 'test result: ok. 1 passed; 0 failed; 0 ignored;' --forbid 'HARNESS' --forbid 'EXPECTED_CLEANUP_HOLD' -- "$library" --exact "$selector" --test-threads=1 --color never
done
python3 - "$proof" "${selectors[@]}" <<'PYCOUNTS'
import json, pathlib, sys
out = pathlib.Path(sys.argv[1])
selectors = sys.argv[2:]
assert len(selectors) == len(set(selectors)) == 12
for index, selector in enumerate(selectors, 1):
    listing = (out/f'list-{index}'/'stdout').read_text().splitlines()
    assert [line for line in listing if line] == [f'{selector}: test', '1 test, 0 benchmarks'], listing
    body = (out/f'body-{index}'/'stdout').read_text().splitlines()
    assert body.count(f'test {selector} ... ok') == 1, body
    summaries = [line for line in body if line.startswith('test result:')]
    assert len(summaries) == 1 and summaries[0].startswith('test result: ok. 1 passed; 0 failed; 0 ignored;'), summaries
    for phase in ('list', 'body'):
        receipt = json.loads((out/f'{phase}-{index}'/'receipt.json').read_text())
        assert receipt['state'] == 'EXACT_COMMAND_OUTCOME_AND_OWNED_SESSION_RETIREMENT_RECORDED'
        assert receipt['exit'] == 0 and receipt['session_closed'] is True and not receipt['errors']
(out/'green-selector-summary.json').write_text(json.dumps({'state': 'TWELVE_EXACT_GREEN_SELECTORS_CAPTURED_PENDING_ROOT_REVIEW', 'selectors': selectors, 'boundary_controls': 4, 'strict_verifier_controls': 8, 'body_passes': 12, 'body_failures': 0, 'body_ignored': 0}, indent=2)+'\n')
PYCOUNTS
printf '%s\n' 'NODE_CLEANUP_GREEN_CAPTURED_PENDING_ROOT_REVIEW'
