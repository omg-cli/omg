#!/usr/bin/env bash
set -euo pipefail
python3 /work/install-qemu-libslirp.py qemu-system-x86
cd /work
dpkg-query -W -f='${binary:Package}\t${Version}\t${Architecture}\n' | sort > packages.tsv
cc --version > compiler.txt
tar --extract --file qemu-10.0.14.tar.xz --no-same-owner
mkdir build
cd build
configure=(../qemu-10.0.14/configure --prefix=/opt/omg-qemu-10.0.14
  --datadir=/opt/omg-qemu-10.0.14/firmware --target-list=x86_64-softmmu
  --enable-kvm --enable-slirp --enable-seccomp --disable-rust --disable-docs
  --disable-download --disable-debug-info)
printf '%s\n' "${configure[@]}" > /work/configure-argv.txt
"${configure[@]}"
cp config-host.mak /work/config-host.mak
ninja -j2 qemu-system-x86_64 qemu-img
mkdir -p /work/opt/omg-qemu-10.0.14/bin
cp qemu-system-x86_64 qemu-img /work/opt/omg-qemu-10.0.14/bin/
mkdir -p /work/opt/omg-qemu-10.0.14/firmware
python3 /work/bundle.py merge-firmware /work/opt/omg-qemu-10.0.14/firmware/qemu \
  /usr/share/qemu /usr/share/seabios > /work/firmware.json
