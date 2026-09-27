#!/usr/bin/env bash
# Bounded native ALPM upgrade through OMG inside a disposable Arch QEMU guest.
set -euo pipefail
[[ $# == 3 ]] || exit 2
mode=$1; binary=$2; guest_user=$3
[[ "$mode" == fast || "$mode" == turbo ]] || exit 2
[[ "$binary" == /* && -x "$binary" && ! -L "$binary" ]] || exit 2
[[ "$guest_user" =~ ^[a-z_][a-z0-9_-]*$ ]] || exit 2
[[ $(id -u) == 0 && -f /etc/arch-release ]] || exit 2
for tool in pacman pacman-conf repo-add bsdtar zstd python3 curl sudo; do
  command -v "$tool" >/dev/null || { printf 'missing fixture tool: %s\nOMG_QEMU_FIXTURE_SETUP_FAILED\n' "$tool" >&2; exit 120; }
done

package=omg-qemu-update-oracle
repo_id=omg-qa-update
config=/etc/pacman.conf
sync_db=/var/lib/pacman/sync/$repo_id.db
[[ -f "$config" && ! -L "$config" && ! -e "$sync_db" && ! -L "$sync_db" ]] ||
  { echo 'OMG_QEMU_FIXTURE_SETUP_FAILED' >&2; exit 120; }
if pacman -Q "$package" >/dev/null 2>&1; then
  echo 'fixture package already installed' >&2
  echo 'OMG_QEMU_FIXTURE_SETUP_FAILED' >&2
  exit 120
fi
base=$(mktemp -d /var/tmp/omg-qemu-arch-update.XXXXXX) ||
  { echo 'OMG_QEMU_FIXTURE_SETUP_FAILED' >&2; exit 120; }
chmod 755 "$base"
config_written=false
server_pid=
phase=setup
cleanup() {
  local status=$? failed=false
  trap - EXIT
  set +e
  if [[ -n "$server_pid" ]]; then
    kill "$server_pid" 2>/dev/null
    wait "$server_pid" 2>/dev/null
    kill -0 "$server_pid" 2>/dev/null && failed=true
  fi
  if pacman -Q "$package" >/dev/null 2>&1; then
    pacman -R --noconfirm "$package" >/dev/null 2>&1 || failed=true
  fi
  if [[ "$config_written" == true ]]; then
    cp -a "$base/original-pacman.conf" "$config" || failed=true
  fi
  rm -f -- "$sync_db" "$sync_db.sig" || failed=true
  rm -f -- /var/cache/pacman/pkg/"$package"-*.pkg.tar.zst || failed=true
  rm -rf -- "$base" || failed=true
  if [[ "$failed" == true ]]; then echo 'OMG_QEMU_FIXTURE_CLEANUP_FAILED' >&2; status=121
  elif [[ "$status" != 0 && "$phase" == setup ]]; then echo 'OMG_QEMU_FIXTURE_SETUP_FAILED' >&2; fi
  exit "$status"
}
trap cleanup EXIT

cp -a "$config" "$base/original-pacman.conf"
mkdir -p "$base/repo"
chmod 755 "$base/repo"
build_package() {
  local version=$1 top="$base/build-$1" archive="$base/repo/$package-$1-1-any.pkg.tar.zst"
  mkdir -p "$top/usr/share/$package"
  printf '%s\n' "$version" > "$top/usr/share/$package/version"
  cat > "$top/.PKGINFO" <<PKG
pkgname = $package
pkgbase = $package
pkgver = $version-1
pkgdesc = QEMU update behavior oracle
url = https://example.invalid
builddate = 1780000000
packager = OMG QEMU
size = 2
arch = any
license = MIT
PKG
  (cd "$top" && bsdtar -cf - .PKGINFO usr) | zstd -q -o "$archive"
  [[ $(pacman -Qp "$archive") == "$package $version-1" ]] || return 120
}
build_package 1
build_package 2
build_package 3
pacman -U --noconfirm "$base/repo/$package-1-1-any.pkg.tar.zst" > "$base/install-v1.log" 2>&1 ||
  { cat "$base/install-v1.log" >&2; exit 120; }
[[ $(pacman -Q "$package") == "$package 1-1" ]] || exit 120
pacman -Q | grep -v "^$package " | LC_ALL=C sort > "$base/system-before.tsv"
pacman -Qqe | grep -vx "$package" | LC_ALL=C sort > "$base/reasons-before.tsv"

cat > "$base/server.py" <<'PY'
import http.server
import pathlib
import sys

directory, port_file = sys.argv[1:]
class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=directory, **kwargs)

    def send_head(self):
        # repo-add can publish two revisions within one HTTP date second.
        # Serve the new database even when pacman/OMG sends an old timestamp.
        if "If-Modified-Since" in self.headers:
            del self.headers["If-Modified-Since"]
        return super().send_head()

server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
pathlib.Path(port_file).write_text(str(server.server_port), encoding="ascii")
server.serve_forever()
PY
python3 "$base/server.py" "$base/repo" "$base/port" > "$base/server.log" 2>&1 &
server_pid=$!
for _ in {1..50}; do
  [[ -s "$base/port" ]] && break
  kill -0 "$server_pid" 2>/dev/null || exit 120
  sleep 0.1
done
[[ -s "$base/port" ]] || exit 120
port=$(cat "$base/port")
[[ "$port" =~ ^[1-9][0-9]{0,4}$ ]] || exit 120

repo-add "$base/repo/$repo_id.db.tar.gz" "$base/repo/$package-1-1-any.pkg.tar.zst" > "$base/repo-v1.log" 2>&1 ||
  { cat "$base/repo-v1.log" >&2; exit 120; }
curl --noproxy '*' -fsS "http://127.0.0.1:$port/$repo_id.db" -o "$base/served-v1.db" || exit 120
config_written=true
printf '[options]\nArchitecture = auto\nSigLevel = Never\n\n[%s]\nServer = http://127.0.0.1:%s\n' "$repo_id" "$port" > "$config"
chmod 644 "$config"
[[ $(pacman-conf --repo-list) == "$repo_id" ]] || exit 120
pacman -Sy --noconfirm > "$base/sync-initial.log" 2>&1 ||
  { cat "$base/sync-initial.log" >&2; exit 120; }
[[ $(pacman -Si "$package" | awk '$1 == "Version" { print $3; exit }') == 1-1 ]] || exit 120

# ALPM compares repository HTTP timestamps at whole-second precision. Ensure
# every published revision has a strictly later Last-Modified value.
sleep 1.1
if [[ "$mode" == fast ]]; then
  repo-add "$base/repo/$repo_id.db.tar.gz" "$base/repo/$package-2-1-any.pkg.tar.zst" > "$base/repo-v2.log" 2>&1 ||
    { cat "$base/repo-v2.log" >&2; exit 120; }
  [[ $(pacman -Si "$package" | awk '$1 == "Version" { print $3; exit }') == 1-1 ]] || exit 120
else
  repo-add "$base/repo/$repo_id.db.tar.gz" "$base/repo/$package-2-1-any.pkg.tar.zst" > "$base/repo-v2.log" 2>&1 ||
    { cat "$base/repo-v2.log" >&2; exit 120; }
  pacman -Sy --noconfirm > "$base/sync-v2.log" 2>&1 ||
    { cat "$base/sync-v2.log" >&2; exit 120; }
  [[ $(pacman -Si "$package" | awk '$1 == "Version" { print $3; exit }') == 2-1 ]] || exit 120
  pacman -Sw --noconfirm "$package" > "$base/download-v2.log" 2>&1 ||
    { cat "$base/download-v2.log" >&2; exit 120; }
  [[ $(pacman -Q "$package") == "$package 1-1" ]] || exit 120
  sleep 1.1
  repo-add "$base/repo/$repo_id.db.tar.gz" "$base/repo/$package-3-1-any.pkg.tar.zst" > "$base/repo-v3.log" 2>&1 ||
    { cat "$base/repo-v3.log" >&2; exit 120; }
  [[ $(pacman -Si "$package" | awk '$1 == "Version" { print $3; exit }') == 2-1 ]] || exit 120
fi
curl --noproxy '*' -fsS "http://127.0.0.1:$port/$repo_id.db" -o "$base/served-next.db" || exit 120
[[ ! -s "$base/server.log" ]] || { cat "$base/server.log" >&2; }
printf 'OMG_QEMU_UPDATE_FIXTURE:before:%s:1\n' "$mode"
phase=product
sudo -H -u "$guest_user" -- "$binary" update "--$mode" --yes
phase=verification
[[ $(pacman -Q "$package") == "$package 2-1" ]] ||
  { echo 'OMG did not upgrade the native ALPM fixture to version 2' >&2; exit 1; }
pacman -Q | grep -v "^$package " | LC_ALL=C sort > "$base/system-after.tsv"
pacman -Qqe | grep -vx "$package" | LC_ALL=C sort > "$base/reasons-after.tsv"
cmp "$base/system-before.tsv" "$base/system-after.tsv" &&
  cmp "$base/reasons-before.tsv" "$base/reasons-after.tsv" ||
  { echo 'OMG changed packages or install reasons outside the bounded fixture' >&2; exit 1; }
printf 'OMG_QEMU_UPDATE_FIXTURE:after:%s:2:native-upgrade\n' "$mode"
