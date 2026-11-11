#!/usr/bin/env bash
set -euo pipefail
os_release=/etc/os-release
source_file=/etc/apt/sources.list.d/ubuntu.sources
mirror_file=/etc/apt/apt-mirrors.txt
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
test -f "$source_file"
test ! -L "$source_file"
test -s "$keyring"
test ! -L "$keyring"
as_root() {
  if [ "$(id -u)" = 0 ]; then "$@"; else sudo -n "$@"; fi
}
work=$(mktemp -d)
trap 'rm -f "$work/sources" "$work/mirrors"; rmdir "$work"' EXIT
scheme=http
if test -s "$ca_bundle"; then scheme=https; fi
render_sources() {
  awk -v suite="$VERSION_CODENAME" -v scheme="$scheme" '
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
          if (value == "mirror+file:/etc/apt/apt-mirrors.txt") {
            $i="URIs: " value
            continue
          }
          if (value !~ /^https?:\/\/(archive|azure\.archive|security)\.ubuntu\.com\/ubuntu\/?$/ &&
              value !~ /^https?:\/\/mirrors\.edge\.kernel\.org\/ubuntu\/?$/) exit 1
          $i="URIs: " scheme "://mirrors.edge.kernel.org/ubuntu/"
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
  ' "$source_file" > "$work/sources"
}
render_sources
uses_mirrors=false
if grep -q '^URIs: mirror+file:/etc/apt/apt-mirrors.txt$' "$work/sources"; then
  test -f "$mirror_file"
  test ! -L "$mirror_file"
  awk '
    /^[ \t]*(#|$)/ { next }
    {
      if ($1 !~ /^https?:\/\/(archive|azure\.archive|security)\.ubuntu\.com\/ubuntu\/?$/ &&
          $1 !~ /^https?:\/\/mirrors\.edge\.kernel\.org\/ubuntu\/?$/) exit 1
      if (NF > 2 || (NF == 2 && $2 !~ /^priority:[0-9]+$/)) exit 1
      count++
    }
    END { if (!count) exit 1 }
  ' "$mirror_file"
  uses_mirrors=true
fi
apply_sources() {
  as_root install -m 644 "$work/sources" "$source_file"
  if "$uses_mirrors"; then
    printf '%s://mirrors.edge.kernel.org/ubuntu/\tpriority:1\n' "$scheme" > "$work/mirrors"
    as_root install -m 644 "$work/mirrors" "$mirror_file"
  fi
}
update() {
  as_root timeout --kill-after=5s 180 apt-get -o APT::Update::Error-Mode=any \
    -o Acquire::Retries=2 -o Acquire::http::Timeout=20 -o Acquire::https::Timeout=20 update
}
apply_sources
update
if [ "$scheme" = http ]; then
  as_root timeout --kill-after=5s 180 apt-get -o Acquire::Retries=2 \
    -o Acquire::http::Timeout=20 install -y --no-install-recommends ca-certificates
  test -s "$ca_bundle"
  scheme=https
  render_sources
  apply_sources
  update
fi
