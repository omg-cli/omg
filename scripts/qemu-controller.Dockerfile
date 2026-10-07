ARG BASE_IMAGE
FROM ${BASE_IMAGE}
ARG QEMU_PACKAGE
ARG FIRMWARE_PACKAGE
ARG SOURCE_SHA
ARG BASE_DIGEST
RUN case "$QEMU_PACKAGE:$FIRMWARE_PACKAGE" in \
      qemu-system-x86:ovmf|qemu-system-arm:qemu-efi-aarch64) ;; \
      *) exit 2 ;; esac \
    && apt-get -o APT::Update::Error-Mode=any -o Acquire::Retries=2 \
         -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30 update \
    && DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::Retries=2 \
         -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30 \
         install -y --no-install-recommends "$QEMU_PACKAGE" qemu-utils \
         cloud-image-utils openssh-client curl ca-certificates "$FIRMWARE_PACKAGE" jq python3
COPY install-qemu-libslirp.py check-qemu-controller.sh /opt/omg-controller/
RUN python3 /opt/omg-controller/install-qemu-libslirp.py "$QEMU_PACKAGE" \
    && bash /opt/omg-controller/check-qemu-controller.sh "$QEMU_PACKAGE" \
    && rm -rf /var/lib/apt/lists/*
LABEL org.opencontainers.image.revision=${SOURCE_SHA} \
      org.opencontainers.image.base.digest=${BASE_DIGEST} \
      org.omg.controller.qemu-package=${QEMU_PACKAGE}
CMD ["sleep", "infinity"]
