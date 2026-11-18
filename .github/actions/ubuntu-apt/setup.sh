#!/usr/bin/env bash
set -euo pipefail
os_release=/etc/os-release
source_file=/etc/apt/sources.list.d/ubuntu.sources
ca_bundle=/etc/ssl/certs/ca-certificates.crt
keyring=/usr/share/keyrings/ubuntu-archive-keyring.gpg
. "$os_release"
case "$ID:$VERSION_ID:${VERSION_CODENAME:-}" in
  ubuntu:24.04:noble|ubuntu:26.04:resolute) ;;
  *) echo 'Unsupported Ubuntu archive identity' >&2; exit 1 ;;
esac
case "$(dpkg --print-architecture)" in
  amd64|amd64v3) ;;
  *) echo 'Unsupported Ubuntu archive architecture' >&2; exit 1 ;;
esac
if ! test -f "$source_file" || test -L "$source_file"; then
  echo 'Ubuntu archive sources must be a regular file' >&2
  exit 1
fi
if ! test -f "$keyring" || ! test -s "$keyring" || test -L "$keyring"; then
  echo 'Ubuntu archive keyring must be a nonempty regular file' >&2
  exit 1
fi
as_root() {
  if [ "$(id -u)" = 0 ]; then "$@"; else sudo -n "$@"; fi
}
work=$(mktemp -d)
trap 'rm -f "$work/sources"; rmdir "$work"' EXIT
scheme=http
if test -s "$ca_bundle"; then scheme=https; fi
render_sources() {
  awk -v suite="$VERSION_CODENAME" -v scheme="$scheme" -v mirror="$1" '
    BEGIN { RS=""; FS="\n" }
    {
      for (key in seen) delete seen[key]
      fields=0
      for (i=1; i<=NF; i++) {
        line=$i
        if (line ~ /^[ \t]*#/) continue
        if (line !~ /^[A-Za-z][A-Za-z-]*:[ \t]*/) exit 1
        key=line; sub(/:.*/, "", key); key=tolower(key)
        value=line; sub(/^[^:]+:[ \t]*/, "", value); sub(/[ \t]+$/, "", value)
        if (seen[key]++) exit 1
        fields++
        if (key == "uris") {
          n=split(value, uris, /[ \t]+/)
          if (!n) exit 1
          for (j=1; j<=n; j++) {
            uri=uris[j]
            if (uri != "mirror+file:/etc/apt/apt-mirrors.txt" &&
                uri !~ /^https?:\/\/(archive|azure\.archive|security)\.ubuntu\.com\/ubuntu\/?$/ &&
                uri !~ /^https?:\/\/mirrors\.edge\.kernel\.org\/ubuntu\/?$/) exit 1
          }
          $i="URIs: " scheme "://" mirror "/ubuntu/"
        }
        if (key == "signed-by" && value != "/usr/share/keyrings/ubuntu-archive-keyring.gpg") exit 1
        if (key == "suites") {
          n=split(value, values, /[ \t]+/)
          if (!n) exit 1
          for (j=1; j<=n; j++)
            if (values[j] != suite && values[j] != suite "-updates" &&
                values[j] != suite "-security" && values[j] != suite "-backports") exit 1
        }
        if (key == "components") {
          n=split(value, values, /[ \t]+/)
          if (!n) exit 1
          for (j=1; j<=n; j++)
            if (values[j] !~ /^(main|restricted|universe|multiverse)$/) exit 1
        }
        if (key == "types" && value !~ /^(deb|deb-src|deb deb-src)$/) exit 1
        if (key ~ /^(trusted|allow-insecure|allow-weak|allow-downgrade-to-insecure)$/ && tolower(value) != "no") exit 1
        if (key ~ /^(check-valid-until|check-date)$/ && tolower(value) != "yes") exit 1
      }
      if (fields && (!seen["uris"] || !seen["suites"] || !seen["components"] ||
          !seen["signed-by"] || !seen["types"])) exit 1
      if (fields) count++
      if (printed++) print ""
      for (i=1; i<=NF; i++) print $i
    }
    END { if (!count) exit 1 }
  ' "$source_file" > "$work/sources" || {
    echo 'Ubuntu archive source definition failed validation' >&2
    return 1
  }
}
apply_sources() {
  as_root install -m 644 "$work/sources" "$source_file"
}
update() {
  as_root timeout --kill-after=5s 180 apt-get -o APT::Update::Error-Mode=any \
    -o Acquire::Retries=2 -o Acquire::http::Timeout=20 -o Acquire::https::Timeout=20 update
}
refresh_sources() {
  local mirror
  for mirror in archive.ubuntu.com mirrors.edge.kernel.org; do
    render_sources "$mirror" || return 1
    apply_sources || return 1
    if update; then
      return 0
    fi
    printf 'Signed Ubuntu index refresh failed via %s\n' "$mirror" >&2
  done
  return 1
}

refresh_sources
if [ "$scheme" = http ]; then
  as_root timeout --kill-after=5s 180 apt-get -o Acquire::Retries=2 \
    -o Acquire::http::Timeout=20 install -y --no-install-recommends ca-certificates
  test -s "$ca_bundle"
  scheme=https
  refresh_sources
fi
