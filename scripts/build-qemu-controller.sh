#!/usr/bin/env bash
set -euo pipefail
[[ $# == 1 ]] || exit 2
output=$1
[[ ! -e "$output" ]] || { printf 'Controller output already exists\n' >&2; exit 2; }
: "${GITHUB_REPOSITORY:?}" "${GITHUB_SHA:?}" "${GITHUB_RUN_ID:?}" "${GITHUB_RUN_ATTEMPT:?}"
[[ $(uname -m) == x86_64 && "$GITHUB_SHA" =~ ^[0-9a-f]{40}$ ]] || exit 2
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
mkdir "$output"
output=$(cd "$output" && pwd)
scratch=$(mktemp -d)
container="omg-controller-build-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT"
builder="omg-controller-builder:$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT"
image="omg-qemu-controller:$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT"
runtime_record="omg-controller-record-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT"
owned=false
record_owned=false
cleanup() {
  if [[ "$owned" == true ]]; then docker rm --force "$container" >/dev/null; fi
  if [[ "$record_owned" == true ]]; then docker rm "$runtime_record" >/dev/null; fi
  rm -rf -- "$scratch"
}
trap cleanup EXIT
for suffix in tar.xz tar.xz.sig; do
  curl --fail --location --proto '=https' --proto-redir '=https' \
    --connect-timeout 20 --max-time 300 --output "$scratch/qemu-10.0.14.$suffix" \
    "https://download.qemu.org/qemu-10.0.14.$suffix"
done
python3 "$here/qemu-controller-bundle.py" authenticate-source \
  "$scratch/qemu-10.0.14.tar.xz" "$scratch/qemu-10.0.14.tar.xz.sig" \
  "$here/../tests/qemu-controller/release-manager.asc" > "$output/authentication.json"
timeout --kill-after=5s 600 docker build --tag "$builder" \
  --file "$here/../tests/qemu-controller/Dockerfile.build" "$here/../tests/qemu-controller"
cp "$here/qemu-controller-bundle.py" "$scratch/bundle.py"
cp "$here/install-qemu-libslirp.py" "$scratch/install-qemu-libslirp.py"
cp "$here/../tests/qemu-controller/compile.sh" "$scratch/compile.sh"
cp "$here/../tests/qemu-controller/Dockerfile.build" "$scratch/Dockerfile.build"
cp "$here/../tests/qemu-controller/Dockerfile.runtime" "$scratch/Dockerfile.runtime"
docker create --name "$container" --memory=8g --memory-swap=8g --cpus=2 --pids-limit=512 \
  --mount "type=bind,source=$scratch,target=/work" "$builder" bash /work/compile.sh > "$output/build-container-id.txt"
owned=true
timeout --kill-after=5s 1800 docker start --attach "$container" > "$output/build.log" 2>&1
[[ $(docker inspect --format '{{.State.ExitCode}}' "$container") == 0 ]]
[[ $(docker inspect --format '{{.State.OOMKilled}}' "$container") == false ]]
for record in packages.tsv compiler.txt configure-argv.txt config-host.mak compile.sh Dockerfile.build Dockerfile.runtime; do
  cp "$scratch/$record" "$output/$record"
done
cp "$here/../tests/qemu-controller/Dockerfile.runtime" "$scratch/Dockerfile"
printf '*\n!Dockerfile\n!install-qemu-libslirp.py\n!opt/\n!opt/**\n' > "$scratch/.dockerignore"
timeout --kill-after=5s 600 docker build --build-arg "SOURCE_SHA=$GITHUB_SHA" --tag "$image" "$scratch"
docker create --name "$runtime_record" "$image" > "$output/runtime-record-container-id.txt"
record_owned=true
docker cp "$runtime_record:/opt/omg-qemu-10.0.14/runtime-packages.tsv" "$output/runtime-packages.tsv"
docker save --output "$output/controller-image.tar" "$image"
python3 "$here/qemu-controller-bundle.py" record "$output" "$scratch/opt" \
  --repository "$GITHUB_REPOSITORY" --source-sha "$GITHUB_SHA" --run-id "$GITHUB_RUN_ID" \
  --run-attempt "$GITHUB_RUN_ATTEMPT" --image-id "$(docker image inspect --format '{{.Id}}' "$image")"
if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  python3 "$here/qemu-controller-bundle.py" outputs "$output" >> "$GITHUB_OUTPUT"
fi
