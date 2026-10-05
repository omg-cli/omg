#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
scratch="$(mktemp -d "${PAPERCLIP_RUN_SCRATCH_DIR:-${TMPDIR:-/tmp}}/release-provenance.XXXXXX")"
trap 'rm -rf "$scratch"' EXIT
source <(sed -n '/^resolve_artifact()/,/^}/p' "$repo_root/scripts/release-smoke.sh")

source <(sed -n '/^validate_checksum()/,/^}/p' "$repo_root/scripts/release-smoke.sh")
source <(sed -n '/^verify_pinned_digest()/,/^}/p' "$repo_root/scripts/release-smoke.sh")
SHA256_BIN="$(command -v sha256sum)"
gh() {
  if [[ "$1 $2" == 'release download' ]]; then
    local destination=''
    while (($#)); do
      if [[ "$1" == --dir ]]; then destination=$2; shift; fi
      shift
    done
    printf 'fixture\n' > "$destination/$archive"
    printf '%s  %s\n' "$(sha256sum "$destination/$archive" | awk '{print $1}')" "$archive" > "$destination/$archive.sha256"
    if [[ "${checksum_mismatch:-0}" == 1 ]]; then
      printf 'replacement\n' > "$destination/$archive"
    fi
    return 0
  fi
  if [[ "$1 $2" == 'attestation verify' ]]; then
    printf '%s\n' "$@" > "$scratch/attestation-args"
    local requested_repo='' requested_ref='' requested_workflow=''
    shift 3
    while (($#)); do
      case "$1" in
        --repo) requested_repo=$2; shift 2 ;;
        --source-ref) requested_ref=$2; shift 2 ;;
        --signer-workflow) requested_workflow=$2; shift 2 ;;
        *) return 99 ;;
      esac
    done
    # Model the CLI's identity constraints against independent fixture claims.
    [[ "$requested_repo" == "$fixture_repo" &&
       "$requested_ref" == "$fixture_ref" &&
       "$requested_workflow" == "$fixture_workflow" ]] || return 1
    return "$attestation_result"
  fi
  return 99
}

tag=v9.9.9
repo=PyRo1121/omg
distro_suffix=-macos-arm64
staged_dir=''
printf 'fixture\n' > "$scratch/pin-subject"
sha256sum "$scratch/pin-subject" | awk '{print $1}' > "$scratch/pins"
digest_pin_file="$scratch/pins"
executor=native
fixture_repo=omg-cli/omg
fixture_ref=refs/tags/v9.9.9
fixture_workflow=omg-cli/omg/.github/workflows/release.yml
attestation_result=1
mkdir "$scratch/rejected"
if resolve_artifact "$scratch/rejected"; then
  printf 'FAIL: invalid provenance accepted before native extraction\n' >&2
  exit 1
fi
[[ -f "$scratch/attestation-args" ]] || { printf 'FAIL: verifier was not called\n' >&2; exit 1; }
grep -Fxq -- '--source-ref' "$scratch/attestation-args"
grep -Fxq -- 'refs/tags/v9.9.9' "$scratch/attestation-args"
grep -Fxq -- '--signer-workflow' "$scratch/attestation-args"
grep -Fxq -- 'omg-cli/omg/.github/workflows/release.yml' "$scratch/attestation-args"
grep -Fxq -- '--repo' "$scratch/attestation-args"
grep -Fxq -- 'omg-cli/omg' "$scratch/attestation-args"

attestation_result=0
mkdir "$scratch/accepted"
resolve_artifact "$scratch/accepted"

# Locally staged test artifacts use the independent pin contract, not a
# published-release attestation. Published smoke jobs do not select this mode.
staged_dir="$scratch/accepted"
attestation_result=1
rm -f "$scratch/attestation-args"
mkdir "$scratch/staged"
resolve_artifact "$scratch/staged"
[[ ! -f "$scratch/attestation-args" ]]

# The same archive trust boundary applies inside containers. These fixtures
# invoke the current resolver and real checksum/pin functions, never a guest.
executor=container
distro_suffix=-x86_64-linux-arch
staged_dir=''
digest_pin_file=''
for rejected_provenance in unattested wrong-workflow wrong-tag; do
  attestation_result=0
  fixture_ref=refs/tags/v9.9.9
  fixture_workflow=omg-cli/omg/.github/workflows/release.yml
  case "$rejected_provenance" in
    unattested) attestation_result=1 ;;
    wrong-workflow) fixture_workflow=omg-cli/omg/.github/workflows/untrusted.yml ;;
    wrong-tag) fixture_ref=refs/tags/v9.9.8 ;;
  esac
  rm -f "$scratch/attestation-args"
  mkdir "$scratch/container-$rejected_provenance"
  if resolve_artifact "$scratch/container-$rejected_provenance"; then
    printf 'FAIL: %s provenance accepted before container extraction\n' "$rejected_provenance" >&2
    exit 1
  fi
  [[ -f "$scratch/attestation-args" ]]
done

attestation_result=0
fixture_ref=refs/tags/v9.9.9
fixture_workflow=omg-cli/omg/.github/workflows/release.yml
mkdir "$scratch/container-accepted"
resolve_artifact "$scratch/container-accepted"
grep -Fxq -- "$scratch/container-accepted/omg-v9.9.9-x86_64-linux-arch.tar.gz" "$scratch/attestation-args"
grep -Fxq -- 'refs/tags/v9.9.9' "$scratch/attestation-args"
grep -Fxq -- 'omg-cli/omg/.github/workflows/release.yml' "$scratch/attestation-args"
grep -Fxq -- 'omg-cli/omg' "$scratch/attestation-args"

checksum_mismatch=1
rm -f "$scratch/attestation-args"
mkdir "$scratch/container-checksum-mismatch"
if resolve_artifact "$scratch/container-checksum-mismatch"; then
  printf 'FAIL: checksum mismatch accepted\n' >&2
  exit 1
fi
[[ ! -f "$scratch/attestation-args" ]]
checksum_mismatch=0

# Staged Linux candidates belong to the trusted release workflow before
# publication/attestation; no independent pin is currently required there.
staged_dir="$scratch/container-accepted"
attestation_result=1
mkdir "$scratch/container-staged"
resolve_artifact "$scratch/container-staged"
[[ ! -f "$scratch/attestation-args" ]]
printf 'PASS: published native/container provenance rejects; verified, checksum-negative and staged controls pass\n'
