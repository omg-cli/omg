FROM registry.cloudflare.com/f1e95b3e1b502cf366dfc81a863695fa/omg-cloud-ci-base@sha256:21eb35d60826d1183e60e9220e6db58dffd1472762c32e8c57c998ea6f24609c
USER root
RUN command -v ip && setpriv --reuid=10001 --regid=10001 --clear-groups ip -statistics -statistics link > /tmp/ip-statistics && grep -q 'RX:' /tmp/ip-statistics && rm /tmp/ip-statistics
COPY services/cloud-ci/runner/package.json services/cloud-ci/runner/bun.lock /opt/omg-ci/
RUN cd /opt/omg-ci && bun install --frozen-lockfile --ignore-scripts
COPY services/cloud-ci/runner/ /opt/omg-ci/
COPY services/cloud-ci/runner/ /opt/omg-ci/runner/
COPY services/cloud-ci/verifier.mjs /opt/omg-ci/verifier.mjs
COPY scripts/rust-source-policy.mjs /scripts/rust-source-policy.mjs
COPY scripts/prepare-node-test-fixture.py /scripts/prepare-node-test-fixture.py
RUN python3 /scripts/prepare-node-test-fixture.py --destination /opt/omg-node-test-fixture && chown -R 10001:10001 /opt/omg-node-test-fixture && setpriv --reuid=10001 --regid=10001 --clear-groups python3 /scripts/prepare-node-test-fixture.py --destination /opt/omg-node-test-fixture
RUN chmod -R a+rX,go-w /opt/omg-ci /scripts
RUN node /opt/omg-ci/verification-envelope-smoke.mjs
RUN node /opt/omg-ci/frozen-rust-inputs-smoke.mjs
RUN node /opt/omg-ci/portable-fixture-smoke.mjs
RUN node /opt/omg-ci/portable-timeout-smoke.mjs
RUN node --input-type=module -e "import assert from 'node:assert/strict'; import {spawnSync} from 'node:child_process'; for(const name of ['source-tree','unit-report','verification','portable-process','rust-evidence','audit-verifier']) await import('/opt/omg-ci/'+name+'.mjs'); await import('/opt/omg-ci/runner/audit-verifier.mjs'); await import('/opt/omg-ci/verifier.mjs'); const result=spawnSync('/usr/local/cargo/bin/rustc',['--version'],{uid:10001,gid:10001,env:{PATH:'/usr/local/cargo/bin:/usr/local/bin:/usr/bin:/bin',RUSTUP_HOME:'/usr/local/rustup',HOME:'/tmp'}}); assert.equal(result.status,0,result.stderr?.toString()); assert.match(result.stdout.toString(),/^rustc 1.95.0 /); console.log('Trusted Rust executor imports and unprivileged compiler access verified');"
