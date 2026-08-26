# syntax=docker/dockerfile:1.7

FROM ubuntu:24.04 AS build

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
      ca-certificates \
      cmake \
      g++-13 \
      git \
      libssl-dev \
      ninja-build \
      openssh-client \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

RUN cmake -S . -B /build -G Ninja \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_C_COMPILER=gcc-13 \
      -DCMAKE_CXX_COMPILER=g++-13 \
      -DANVIL_INSTALL=OFF \
      -DANVIL_TESTS=OFF \
    && cmake --build /build --target anvil --parallel

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

FROM build AS probe-build

RUN g++-13 -std=c++23 -O2 -Wall -Wextra -Wpedantic \
      /src/test/container_probe.cpp -o /container-probe

FROM build AS ssh-test-client

FROM scratch AS runtime-base

COPY --from=build /runtime/ /

USER 65532:65532
WORKDIR /var/lib/anvil
VOLUME ["/var/lib/anvil"]
EXPOSE 2222
ENTRYPOINT ["/usr/local/bin/anvil"]

FROM runtime-base AS container-test

COPY --from=probe-build --chown=65532:65532 /container-probe /usr/local/bin/anvil-container-probe
ENTRYPOINT ["/usr/local/bin/anvil-container-probe"]

FROM runtime-base AS runtime
