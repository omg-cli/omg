FROM node:24.21.0-bookworm-slim@sha256:d6aa754f16b3197301076f047b5def2f02ea1dbbc2ca920407d46d7ec7f87b20 AS node-runtime
FROM rust:1.95.0-slim-bookworm@sha256:6f9e63259f12e1e599296f5ecfed2bae46de4af0ee0525dd8b89c046e236d5c5 AS rust-runtime
RUN rustup component add rustfmt clippy --toolchain 1.95.0
FROM docker.io/cloudflare/sandbox:0.12.12@sha256:13ce62698fbf15e616d3d8b82ea58860c5ec2c82c610565e6adc5e9ce974a107
USER root
COPY --from=node-runtime /usr/local/bin/node /usr/local/bin/node
COPY --from=rust-runtime /usr/local/cargo /usr/local/cargo
COPY --from=rust-runtime /usr/local/rustup /usr/local/rustup
ENV RUSTUP_HOME=/usr/local/rustup
ENV PATH=/opt/omg-python/bin:/usr/local/cargo/bin:/usr/local/bin:/usr/bin:/bin
RUN apt-get update && apt-get install -y --no-install-recommends curl unzip ca-certificates git squashfs-tools build-essential pkg-config libssl-dev libarchive-dev clang cmake python3 python3-venv make fish util-linux sudo && rm -rf /var/lib/apt/lists/*
RUN curl --proto '=https' --tlsv1.2 -fsSL https://github.com/astral-sh/python-build-standalone/releases/download/20261020/cpython-3.12.15%2B20261020-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz -o /tmp/python.tar.gz && echo '7d6ef1164fb94c4b60d913340610fc7e0ef8e3d1b705aa5628b299b08cbdd4b5  /tmp/python.tar.gz' | sha256sum -c - && mkdir /opt/omg-python && tar -xzf /tmp/python.tar.gz --strip-components=1 -C /opt/omg-python && rm /tmp/python.tar.gz && chmod -R a+rX,go-w /opt/omg-python && python3 -c 'import sys,tomllib,venv; assert sys.version_info[:3] == (3,12,15)' && test -x /usr/bin/sudo
RUN curl -fsSL https://github.com/oven-sh/bun/releases/download/bun-v1.4.2/bun-linux-x64.zip -o /tmp/bun.zip && unzip -q /tmp/bun.zip -d /tmp/bun-install && echo 'a83d263767d839e4d2649ca8e35d07159c7afc99afdc96d731ced29e056dda0c  /tmp/bun-install/bun-linux-x64/bun' | sha256sum -c - && install /tmp/bun-install/bun-linux-x64/bun /usr/local/bin/bun && rm -rf /tmp/bun.zip /tmp/bun-install && test "$(bun --revision)" = '1.4.2+744846f84' && test "$(node --version)" = 'v24.21.0' && rustc --version | grep '^rustc 1.95.0 '
RUN curl -fsSL https://github.com/nextest-rs/nextest/releases/download/cargo-nextest-0.9.148/cargo-nextest-0.9.148-x86_64-unknown-linux-musl.tar.gz -o /tmp/nextest.tar.gz && echo 'bf92cb81450872d960ffa13857a83084d557ec0cdc141663d263bb23ef756f97  /tmp/nextest.tar.gz' | sha256sum -c - && tar -xzf /tmp/nextest.tar.gz -C /usr/local/cargo/bin && rm /tmp/nextest.tar.gz && cargo nextest --version
RUN chmod -R a+rX,go-w /usr/local/cargo /usr/local/rustup
COPY services/cloud-ci/runner/package.json services/cloud-ci/runner/bun.lock /opt/omg-ci/
RUN cd /opt/omg-ci && bun install --frozen-lockfile --ignore-scripts
COPY services/cloud-ci/runner/ /opt/omg-ci/
COPY services/cloud-ci/runner/ /opt/omg-ci/runner/
COPY services/cloud-ci/verifier.mjs /opt/omg-ci/verifier.mjs
COPY scripts/rust-source-policy.mjs /scripts/rust-source-policy.mjs
RUN chmod -R a+rX,go-w /opt/omg-ci /scripts
RUN node /opt/omg-ci/verification-envelope-smoke.mjs
RUN node /opt/omg-ci/frozen-rust-inputs-smoke.mjs
RUN node /opt/omg-ci/portable-fixture-smoke.mjs
RUN node --input-type=module -e "import assert from 'node:assert/strict'; import {spawnSync} from 'node:child_process'; for(const name of ['source-tree','unit-report','verification','portable-process','rust-evidence','audit-verifier']) await import('/opt/omg-ci/'+name+'.mjs'); await import('/opt/omg-ci/runner/audit-verifier.mjs'); await import('/opt/omg-ci/verifier.mjs'); const result=spawnSync('/usr/local/cargo/bin/rustc',['--version'],{uid:10001,gid:10001,env:{PATH:'/usr/local/cargo/bin:/usr/local/bin:/usr/bin:/bin',RUSTUP_HOME:'/usr/local/rustup',HOME:'/tmp'}}); assert.equal(result.status,0,result.stderr?.toString()); assert.match(result.stdout.toString(),/^rustc 1.95.0 /); console.log('Trusted Rust executor imports and unprivileged compiler access verified');"
