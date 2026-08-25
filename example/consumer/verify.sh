#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CONSUMER_DIR="${REPO_ROOT}/example/consumer"
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

run_mode() {
  local mode="$1"
  shift
  local build="${WORK}/build-${mode}"

  cmake -S "${CONSUMER_DIR}" -B "${build}" \
    -DCONSUMER_MODE="${mode}" "$@"
  cmake --build "${build}" --parallel
  "${build}/anvil_loader_consumer"
}

run_mode add_subdirectory -DANVIL_SOURCE_DIR="${REPO_ROOT}"

SNAPSHOT="${WORK}/snapshot"
mkdir -p "${SNAPSHOT}"
(
  cd "${REPO_ROOT}"
  git ls-files --cached --others --exclude-standard -z |
    xargs -0 cp -p --parents -t "${SNAPSHOT}"
  git -C "${SNAPSHOT}" init -q -b main
  git -C "${SNAPSHOT}" add -A
  git -C "${SNAPSHOT}" -c user.email=verify@example.invalid \
    -c user.name=verify commit -qm snapshot
)
run_mode fetchcontent \
  -DANVIL_GIT_REPOSITORY="file://${SNAPSHOT}" \
  -DANVIL_GIT_TAG="$(git -C "${SNAPSHOT}" rev-parse HEAD)"

PREFIX="${WORK}/prefix"
cmake -S "${REPO_ROOT}" -B "${WORK}/build-install" \
  -DANVIL_TESTS=OFF -DCMAKE_INSTALL_PREFIX="${PREFIX}"
cmake --build "${WORK}/build-install" --parallel
cmake --install "${WORK}/build-install"
run_mode find_package -DCMAKE_PREFIX_PATH="${PREFIX}"
