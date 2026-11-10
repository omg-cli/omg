FROM rust:1.95.0-slim-bookworm@sha256:6f9e63259f12e1e599296f5ecfed2bae46de4af0ee0525dd8b89c046e236d5c5 AS rust-runtime
FROM ubuntu:24.04@sha256:78d4744ead1f5b19b04d0df558ab182a5300903900755e515b2ca4d10eb2044d
USER root
COPY --from=rust-runtime /usr/local/cargo /usr/local/cargo
COPY --from=rust-runtime /usr/local/rustup /usr/local/rustup
ENV RUSTUP_HOME=/usr/local/rustup
ENV PATH=/usr/local/cargo/bin:/usr/local/bin:/usr/bin:/bin
RUN apt-get update --error-on=any && apt-get install -y --no-install-recommends ca-certificates git build-essential pkg-config libssl-dev libapt-pkg-dev python3 python3-apt clang cmake zlib1g-dev liblzma-dev libbz2-dev util-linux procps
RUN . /etc/os-release && test "$ID" = ubuntu && test "$VERSION_ID" = 24.04 && test "$(uname -m)" = x86_64 && rustc --version | grep '^rustc 1.95.0 ' && /usr/bin/python3 -I -c 'import apt_pkg,sys; assert sys.version_info[:2] == (3,12); apt_pkg.init(); cache=apt_pkg.Cache(None); dep=apt_pkg.DepCache(cache); assert sum(1 for package in cache.packages if dep.get_candidate_ver(package) or package.current_ver) >= 25000'
COPY services/ci/run.py /opt/ci/run.py
COPY scripts/build-comparison.py /opt/ci/build-comparison.py
COPY scripts/test-debian-daemon-catalog.py /opt/ci/test-debian-daemon-catalog.py
RUN chmod -R a+rX,go-w /opt/ci /usr/local/cargo /usr/local/rustup
WORKDIR /
ENTRYPOINT ["sleep", "infinity"]
