# syntax=docker/dockerfile:1.7

FROM ubuntu:24.04 AS build-base

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
      ca-certificates \
      cmake \
      g++-13 \
      git \
      libsqlite3-dev \
      libssl-dev \
      ninja-build \
      openssh-client \
      python3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

FROM build-base AS production-build

RUN cmake -S . -B /build -G Ninja \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_C_COMPILER=gcc-13 \
      -DCMAKE_CXX_COMPILER=g++-13 \
      -DCMAKE_TOOLCHAIN_FILE=cmake/toolchain/hardened.cmake \
      -DANVIL_INSTALL=OFF \
      -DANVIL_TESTS=OFF \
    && cmake --build /build --target anvil --parallel \
    && python3 -B cmake/verify_elf_hardening.py /build/anvil

FROM production-build AS production-rootfs

RUN set -eux; \
    install -D -m 0755 /build/anvil /runtime/usr/local/bin/anvil; \
    install -d -m 0755 /runtime/etc /runtime/etc/ssl /runtime/var/lib/anvil /runtime/tmp; \
    ldd /build/anvil \
      | awk '/=> \// { print $3 } $1 ~ /^\// { print $1 }' \
      | sort -u \
      | xargs -r -I '{}' cp --parents '{}' /runtime; \
    if [ -f /etc/ssl/openssl.cnf ]; then \
      cp --parents /etc/ssl/openssl.cnf /runtime; \
    fi; \
    if [ -f /etc/ssl/certs/ca-certificates.crt ]; then \
      cp --parents /etc/ssl/certs/ca-certificates.crt /runtime; \
    fi; \
    printf 'anvil:x:65532:65532:Anvil:/var/lib/anvil:/nonexistent\n' > /runtime/etc/passwd; \
    printf 'anvil:x:65532:\n' > /runtime/etc/group; \
    touch /runtime/var/lib/anvil/.volume-owner; \
    chmod 1777 /runtime/tmp; \
    chown -R 65532:65532 /runtime/var/lib/anvil /runtime/tmp

FROM build-base AS staging-build

RUN cmake -S . -B /build -G Ninja \
      -DCMAKE_BUILD_TYPE=RelWithDebInfo \
      -DCMAKE_C_COMPILER=gcc-13 \
      -DCMAKE_CXX_COMPILER=g++-13 \
      -DCMAKE_TOOLCHAIN_FILE=cmake/toolchain/address-undefined.cmake \
      -DANVIL_INSTALL=OFF \
      -DANVIL_TESTS=OFF \
    && cmake --build /build --target anvil --parallel

FROM staging-build AS staging-rootfs

RUN set -eux; \
    install -D -m 0755 /build/anvil /runtime/usr/local/bin/anvil; \
    install -D -m 0755 /usr/bin/addr2line /runtime/usr/bin/addr2line; \
    install -d -m 0755 /runtime/etc /runtime/etc/ssl /runtime/var/lib/anvil /runtime/tmp; \
    ldd /build/anvil /usr/bin/addr2line \
      | awk '/=> \// { print $3 } $1 ~ /^\/[^:]+$/ { print $1 }' \
      | sort -u \
      | xargs -r -I '{}' cp --parents '{}' /runtime; \
    if [ -f /etc/ssl/openssl.cnf ]; then \
      cp --parents /etc/ssl/openssl.cnf /runtime; \
    fi; \
    if [ -f /etc/ssl/certs/ca-certificates.crt ]; then \
      cp --parents /etc/ssl/certs/ca-certificates.crt /runtime; \
    fi; \
    printf 'anvil:x:65532:65532:Anvil:/var/lib/anvil:/nonexistent\n' > /runtime/etc/passwd; \
    printf 'anvil:x:65532:\n' > /runtime/etc/group; \
    touch /runtime/var/lib/anvil/.volume-owner; \
    chmod 1777 /runtime/tmp; \
    chown -R 65532:65532 /runtime/var/lib/anvil /runtime/tmp

FROM build-base AS probe-build

RUN g++-13 -std=c++23 -O2 -Wall -Wextra -Wpedantic \
      /src/test/container_probe.cpp -o /container-probe

FROM build-base AS ssh-test-client

FROM scratch AS runtime-base

COPY --from=production-rootfs /runtime/ /

USER 65532:65532
WORKDIR /var/lib/anvil
VOLUME ["/var/lib/anvil"]
EXPOSE 2222
ENTRYPOINT ["/usr/local/bin/anvil"]

FROM runtime-base AS container-test

COPY --from=probe-build --chown=65532:65532 /container-probe /usr/local/bin/anvil-container-probe
ENTRYPOINT ["/usr/local/bin/anvil-container-probe"]

FROM runtime-base AS runtime

FROM scratch AS staging

COPY --from=staging-rootfs /runtime/ /

ENV PATH=/usr/local/bin:/usr/bin
ENV ASAN_OPTIONS=abort_on_error=1:detect_leaks=1:strict_string_checks=1:allow_addr2line=1
ENV UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1

USER 65532:65532
WORKDIR /var/lib/anvil
VOLUME ["/var/lib/anvil"]
EXPOSE 2222
ENTRYPOINT ["/usr/local/bin/anvil"]
