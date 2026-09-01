#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import os
import pathlib
import subprocess
import sys
import tarfile
import tempfile
import time
from collections.abc import Sequence


ROOT = pathlib.Path(__file__).resolve().parents[1]
RUNTIME_IMAGE = "anvil:container-test"
PROBE_IMAGE = "anvil-container-probe:container-test"
COMPOSE_TEST_IMAGE = "anvil:container-compose-test"
SSH_CLIENT_BASE_IMAGE = "anvil-ssh-client:container-test-base"
SSH_CLIENT_IMAGE = "anvil-ssh-client:container-test"
EGRESS_HOST = "1.1.1.1"
EGRESS_PORT = "443"


def run(arguments: Sequence[str], *, env: dict[str, str] | None = None,
        check: bool = True, input_bytes: bytes | None = None,
        timeout: float | None = None) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(arguments, cwd=ROOT, env=env, check=check, input=input_bytes,
                          capture_output=True, timeout=timeout)


def compose(arguments: Sequence[str], env: dict[str, str], *, egress: bool = False,
            test_override: pathlib.Path | None = None,
            check: bool = True) -> subprocess.CompletedProcess[bytes]:
    command = ["docker", "compose", "-f", str(ROOT / "compose.yaml")]
    if egress:
        command.extend(["-f", str(ROOT / "compose.egress.yaml")])
    if test_override is not None:
        command.extend(["-f", str(test_override)])
    command.extend(arguments)
    return run(command, env=env, check=check)


def wait_for_port(port: int, timeout: float = 15.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = probe(["connect", "127.0.0.1", str(port)], extra=["--network", "host"],
                       check=False)
        if result.returncode == 0:
            return
        time.sleep(0.1)
    raise AssertionError(f"container did not listen on port {port}")


def container_id(env: dict[str, str], test_override: pathlib.Path, *, egress: bool = False) -> str:
    result = compose(["ps", "-q", "anvil"], env, egress=egress,
                     test_override=test_override)
    identifier = result.stdout.decode().strip()
    if not identifier:
        raise AssertionError("Compose did not report the Anvil container")
    return identifier


def inspect_container(identifier: str) -> dict[str, object]:
    result = run(["docker", "inspect", identifier])
    return json.loads(result.stdout)[0]


def published_port(inspection: dict[str, object]) -> int:
    settings = inspection["NetworkSettings"]
    assert isinstance(settings, dict)
    ports = settings["Ports"]
    assert isinstance(ports, dict)
    bindings = ports["2222/tcp"]
    if not isinstance(bindings, list) or not bindings:
        raise AssertionError(f"container port 2222 is not published: {bindings!r}")
    return int(bindings[0]["HostPort"])


def assert_runtime_filesystem() -> None:
    created = run(["docker", "create", RUNTIME_IMAGE, "--help"]).stdout.decode().strip()
    if not created:
        raise AssertionError("docker create returned no container id")
    forbidden = {
        "bin/sh", "bin/bash", "bin/busybox", "usr/bin/apt", "usr/bin/apt-get",
        "usr/bin/dnf", "usr/bin/yum", "sbin/apk", "usr/bin/microdnf",
    }
    try:
        process = subprocess.Popen(["docker", "export", created], cwd=ROOT,
                                   stdout=subprocess.PIPE)
        assert process.stdout is not None
        names: set[str] = set()
        executable: tarfile.TarInfo | None = None
        state_directory: tarfile.TarInfo | None = None
        with tarfile.open(fileobj=process.stdout, mode="r|") as archive:
            for member in archive:
                name = member.name.removeprefix("./")
                names.add(name)
                if name == "usr/local/bin/anvil":
                    executable = member
                elif name.rstrip("/") == "var/lib/anvil":
                    state_directory = member
        if process.wait() != 0:
            raise AssertionError("docker export failed")
        present = forbidden & names
        if present:
            raise AssertionError(f"runtime image contains forbidden tools: {sorted(present)}")
        required_notices = {
            "usr/share/licenses/anvil/LICENSE.md",
            "usr/share/licenses/anvil/THIRD_PARTY_LICENSES.md",
        }
        missing_notices = required_notices - names
        if missing_notices:
            raise AssertionError(
                f"runtime image omits license notices: {sorted(missing_notices)}"
            )
        if executable is None or executable.uid != 0 or executable.gid != 0:
            raise AssertionError("runtime executable is not owned by root")
        if executable.mode & 0o022:
            raise AssertionError("runtime executable is writable outside root")
        if state_directory is None or state_directory.uid != 65532 or state_directory.gid != 65532:
            raise AssertionError("persistent state directory is not owned by the runtime user")
    finally:
        run(["docker", "rm", "--force", created], check=False)


def probe(arguments: Sequence[str], *, extra: Sequence[str] = (),
          check: bool = True) -> subprocess.CompletedProcess[bytes]:
    return run(["docker", "run", "--rm", *extra, PROBE_IMAGE, *arguments], check=check,
               timeout=10)


def assert_write_policy(volume: str) -> None:
    common = ["--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=16m,mode=1777"]
    refused = probe(["write", "/etc/anvil-write-probe"], extra=common, check=False)
    if refused.returncode == 0:
        raise AssertionError("read-only root filesystem accepted a write")
    probe(["write", "/tmp/anvil-write-probe"], extra=common)
    probe(["write", "/var/lib/anvil/anvil-write-probe"],
          extra=[*common, "--volume", f"{volume}:/var/lib/anvil"])


def assert_database_persisted(volume: str) -> None:
    probe(["file", "/var/lib/anvil/anvil.db"],
          extra=["--volume", f"{volume}:/var/lib/anvil"])


def wait_for_backup(volume: str, timeout: float = 15.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = probe(
            ["backup-directory", "/var/lib/anvil/backups"],
            extra=["--volume", f"{volume}:/var/lib/anvil"],
            check=False,
        )
        if result.returncode == 0:
            return
        time.sleep(0.1)
    raise AssertionError("container did not publish a complete backup on its volume")


def assert_compose_posture(configuration: dict[str, object], inspection: dict[str, object]) -> None:
    services = configuration["services"]
    assert isinstance(services, dict)
    service = services["anvil"]
    assert isinstance(service, dict)
    if service.get("read_only") is not True:
        raise AssertionError("Compose root filesystem is not read-only")
    secrets = service.get("secrets")
    if not isinstance(secrets, list) or not any(
        isinstance(secret, dict) and secret.get("source") == "authorized_key" for secret in secrets
    ):
        raise AssertionError("Compose does not mount the authorized key as a secret")
    if not any(
        isinstance(secret, dict) and secret.get("source") == "tos_text" for secret in secrets
    ):
        raise AssertionError("Compose does not mount the TOS text as a secret")
    command = service.get("command")
    if not isinstance(command, list) or not any(
        isinstance(argument, str) and argument.endswith("=/run/secrets/authorized_key")
        for argument in command
    ):
        raise AssertionError("Compose does not read the authorized key from the secret mount")
    if "--health-bind-address" not in command or "127.0.0.1" not in command:
        raise AssertionError("Compose does not keep the health listener on loopback")
    if "--backup-directory" not in command or "/var/lib/anvil/backups" not in command:
        raise AssertionError("Compose does not keep backups on the persistent volume")
    if "--tos-version" not in command or "--tos-file" not in command:
        raise AssertionError("Compose does not configure the versioned TOS")
    if command[command.index("--tos-file") + 1] != "/run/secrets/tos_text":
        raise AssertionError("Compose does not read TOS text from its secret mount")
    invite_defaults = {
        "--invites-per-user": "5",
        "--invite-regeneration-seconds": "2592000",
        "--invite-expiration-seconds": "604800",
        "--notify-inviters-on-moderation": "off",
    }
    for option, expected in invite_defaults.items():
        if (
            option not in command
            or command.index(option) + 1 >= len(command)
            or command[command.index(option) + 1] != expected
        ):
            raise AssertionError(f"Compose invite default is wrong for {option}")
    published = service.get("ports")
    if not isinstance(published, list) or any(
        isinstance(item, dict) and item.get("target") != 2222 for item in published
    ):
        raise AssertionError(f"Compose publishes a non-SSH port: {published!r}")

    config = inspection["Config"]
    host = inspection["HostConfig"]
    assert isinstance(config, dict) and isinstance(host, dict)
    if config.get("User") != "65532:65532":
        raise AssertionError(f"unexpected runtime user: {config.get('User')!r}")
    if host.get("ReadonlyRootfs") is not True:
        raise AssertionError("Docker did not apply the read-only root filesystem")
    if host.get("CapDrop") != ["ALL"]:
        raise AssertionError(f"capabilities were not all dropped: {host.get('CapDrop')!r}")
    security = set(host.get("SecurityOpt") or [])
    if "no-new-privileges:true" not in security:
        raise AssertionError(f"no-new-privileges missing: {sorted(security)!r}")
    if not any(option.startswith("seccomp=") and option != "seccomp=unconfined"
               for option in security):
        raise AssertionError(f"seccomp profile missing: {sorted(security)!r}")
    if host.get("Memory") != 512 * 1024 * 1024:
        raise AssertionError(f"unexpected memory limit: {host.get('Memory')!r}")
    if host.get("NanoCpus") != 2_000_000_000:
        raise AssertionError(f"unexpected CPU limit: {host.get('NanoCpus')!r}")
    if host.get("PidsLimit") != 256:
        raise AssertionError(f"unexpected PID limit: {host.get('PidsLimit')!r}")


def scan_host_key(port: int) -> bytes:
    result = run([
        "docker", "run", "--rm", "--network", "host", SSH_CLIENT_IMAGE,
        "ssh-keyscan", "-T", "5", "-t", "ed25519", "-p", str(port), "127.0.0.1",
    ], check=False)
    lines = [line for line in result.stdout.splitlines() if line and not line.startswith(b"#")]
    if not lines:
        raise AssertionError(f"ssh-keyscan returned no host key: {result.stderr!r}")
    return lines[0].split(maxsplit=1)[1]


def assert_ssh_session(port: int, user: str) -> None:
    command = [
        "docker", "run", "--rm", "--interactive", "--network", "host", SSH_CLIENT_IMAGE,
        "ssh", "-tt", "-i", "/client_key", "-p", str(port),
        "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR",
        f"{user}@127.0.0.1",
    ]
    result = run(
        command, check=False, input_bytes=b"ACCEPT\ncontainer-smoke\x1b", timeout=15
    )
    if b"container-smoke" not in result.stdout:
        raise AssertionError(
            f"SSH smoke test did not echo input\nstdout={result.stdout!r}\nstderr={result.stderr!r}"
        )


def assert_egress(identifier: str, allowed: bool) -> None:
    result = probe(["connect", EGRESS_HOST, EGRESS_PORT],
                   extra=["--network", f"container:{identifier}"], check=False)
    if allowed and result.returncode != 0:
        raise AssertionError(f"egress override did not open egress: {result.stderr!r}")
    if not allowed and result.returncode == 0:
        raise AssertionError("default non-masquerading network allowed egress")


def main(runtime_target: str = "runtime") -> int:
    run(
        ["docker", "build", "--target", runtime_target, "--tag", RUNTIME_IMAGE, "."],
        timeout=900,
    )
    run(["docker", "build", "--target", "container-test", "--tag", PROBE_IMAGE, "."],
        timeout=900)
    run(["docker", "build", "--target", "ssh-test-client", "--tag", SSH_CLIENT_BASE_IMAGE,
         "."], timeout=900)
    assert_runtime_filesystem()

    # The Docker daemon may run outside the client's mount namespace. Build
    # temporary keys into test-only images so the client transfers them through
    # a build context instead of assuming bind-source paths exist on the daemon.
    with tempfile.TemporaryDirectory(prefix=".container-test-", dir=ROOT) as raw_directory:
        directory = pathlib.Path(raw_directory)
        private_key = directory / "client_key"
        run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(private_key)])
        image_context = directory / "image"
        image_context.mkdir()
        (image_context / "Dockerfile").write_text(
            f"FROM {RUNTIME_IMAGE}\n"
            "COPY --chown=65532:65532 client_key.pub /run/anvil-test-authorized-key\n"
            "COPY --chown=65532:65532 tos.txt /run/anvil-test-tos\n",
            encoding="utf-8",
        )
        (image_context / "client_key.pub").write_bytes(
            private_key.with_suffix(".pub").read_bytes()
        )
        (image_context / "tos.txt").write_text("Test terms\n", encoding="utf-8")
        tos_file = directory / "tos.txt"
        tos_file.write_text("Test terms\n", encoding="utf-8")
        run(["docker", "build", "--tag", COMPOSE_TEST_IMAGE, str(image_context)], timeout=120)

        ssh_context = directory / "ssh-client"
        ssh_context.mkdir()
        (ssh_context / "Dockerfile").write_text(
            f"FROM {SSH_CLIENT_BASE_IMAGE}\n"
            "COPY --chmod=0600 client_key /client_key\n",
            encoding="utf-8",
        )
        (ssh_context / "client_key").write_bytes(private_key.read_bytes())
        run(["docker", "build", "--tag", SSH_CLIENT_IMAGE, str(ssh_context)], timeout=120)

        test_override = directory / "compose.test.yaml"
        test_override.write_text(
            "services:\n"
            "  anvil:\n"
            f"    image: {COMPOSE_TEST_IMAGE}\n"
            "    secrets: !reset []\n"
            "    command:\n"
            "      - --bind-address\n"
            "      - 0.0.0.0\n"
            "      - --port\n"
            "      - '2222'\n"
            "      - --database\n"
            "      - /var/lib/anvil/anvil.db\n"
            "      - --tos-version\n"
            "      - v1\n"
            "      - --tos-file\n"
            "      - /run/anvil-test-tos\n"
            "      - --backup-directory\n"
            "      - /var/lib/anvil/backups\n"
            "      - --backup-interval-seconds\n"
            "      - '3600'\n"
            "      - --backup-retention-seconds\n"
            "      - '604800'\n"
            "      - --host-key\n"
            "      - /var/lib/anvil/host_key\n"
            "      - --authorized-key\n"
            "      - container-test=/run/anvil-test-authorized-key\n",
            encoding="utf-8",
        )
        project = f"anvil-container-{os.getpid()}"
        env = os.environ.copy()
        env.update({
            "ANVIL_AUTHORIZED_KEY": str(private_key) + ".pub",
            "ANVIL_TOS_FILE": str(tos_file),
            "ANVIL_TOS_VERSION": "v1",
            "ANVIL_IMAGE_TAG": "container-test",
            "ANVIL_PORT": "0",
            "ANVIL_USER": "container-test",
            "COMPOSE_PROJECT_NAME": project,
        })
        volume = f"{project}_anvil-state"

        default_configuration = json.loads(compose(["config", "--format", "json"], env).stdout)
        override_configuration = json.loads(
            compose(["config", "--format", "json"], env, egress=True).stdout
        )
        invite_env = env | {
            "ANVIL_INVITES_PER_USER": "9",
            "ANVIL_INVITE_REGENERATION_SECONDS": "60",
            "ANVIL_INVITE_EXPIRATION_SECONDS": "120",
            "ANVIL_NOTIFY_INVITERS_ON_MODERATION": "on",
        }
        invite_configuration = json.loads(
            compose(["config", "--format", "json"], invite_env).stdout
        )
        invite_command = invite_configuration["services"]["anvil"]["command"]
        for option, expected in {
            "--invites-per-user": "9",
            "--invite-regeneration-seconds": "60",
            "--invite-expiration-seconds": "120",
            "--notify-inviters-on-moderation": "on",
        }.items():
            assert invite_command[invite_command.index(option) + 1] == expected
        masquerade_option = "com.docker.network.bridge.enable_ip_masquerade"
        default_options = default_configuration["networks"]["default"].get("driver_opts", {})
        override_options = override_configuration["networks"]["default"].get("driver_opts", {})
        if default_options.get(masquerade_option) != "false":
            raise AssertionError("default Compose network enables outbound masquerading")
        if override_options.get(masquerade_option) != "true":
            raise AssertionError("egress override did not enable outbound masquerading")

        try:
            compose(["up", "--detach", "--no-build"], env, test_override=test_override)
            identifier = container_id(env, test_override)
            inspection = inspect_container(identifier)
            port = published_port(inspection)
            try:
                wait_for_port(port)
            except AssertionError:
                sys.stderr.buffer.write(
                    compose(["logs", "--no-color"], env, test_override=test_override,
                            check=False).stdout
                )
                raise
            assert_compose_posture(default_configuration, inspection)
            assert_write_policy(volume)
            assert_database_persisted(volume)
            wait_for_backup(volume)
            first_key = scan_host_key(port)
            assert_ssh_session(port, "container-test")
            assert_egress(identifier, allowed=False)

            compose(["down"], env, test_override=test_override)
            compose(["up", "--detach", "--no-build"], env, egress=True,
                    test_override=test_override)
            identifier = container_id(env, test_override, egress=True)
            port = published_port(inspect_container(identifier))
            try:
                wait_for_port(port)
            except AssertionError:
                sys.stderr.buffer.write(
                    compose(["logs", "--no-color"], env, egress=True,
                            test_override=test_override, check=False).stdout
                )
                raise
            if scan_host_key(port) != first_key:
                raise AssertionError("container recreation changed the persistent host identity")
            assert_database_persisted(volume)
            wait_for_backup(volume)
            assert_egress(identifier, allowed=True)
        finally:
            compose(["down", "--volumes", "--remove-orphans"], env, egress=True,
                    test_override=test_override, check=False)

    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--runtime-target", choices=("runtime", "staging"), default="runtime"
    )
    arguments = parser.parse_args()
    try:
        raise SystemExit(main(arguments.runtime_target))
    except subprocess.CalledProcessError as error:
        sys.stderr.buffer.write(error.stdout or b"")
        sys.stderr.buffer.write(error.stderr or b"")
        raise
