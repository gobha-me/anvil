#!/usr/bin/env python3

from __future__ import annotations

import os
import pathlib
import select
import signal
import socket
import subprocess
import sys
import tempfile
import time


def reserve_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def run_checked(command: list[str]) -> None:
    subprocess.run(command, check=True, stdout=subprocess.DEVNULL,
                   stderr=subprocess.PIPE, timeout=15)


def wait_until_listening(process: subprocess.Popen[bytes]) -> None:
    assert process.stdout is not None
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if process.poll() is not None:
            stdout, stderr = process.communicate(timeout=1)
            raise AssertionError(
                f"server exited before listening ({process.returncode})\n"
                f"stdout={stdout!r}\nstderr={stderr!r}"
            )
        readable, _, _ = select.select([process.stdout], [], [], 0.1)
        if readable and b"anvil: listening on " in process.stdout.readline():
            return
    raise AssertionError("server did not begin listening")


def start_server(executable: pathlib.Path, port: int, host_key: pathlib.Path,
                 client_key: pathlib.Path, options: list[str]) -> subprocess.Popen[bytes]:
    process = subprocess.Popen(
        [
            str(executable),
            "--bind-address", "127.0.0.1",
            "--port", str(port),
            "--host-key", str(host_key),
            "--authorized-key", f"tester={client_key}.pub",
        ] + options,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    wait_until_listening(process)
    return process


def stop_server(process: subprocess.Popen[bytes]) -> bytes:
    if process.poll() is None:
        process.send_signal(signal.SIGTERM)
    try:
        stdout, stderr = process.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        stdout, stderr = process.communicate(timeout=5)
        raise AssertionError(f"server did not shut down\nstdout={stdout!r}\nstderr={stderr!r}")
    assert process.returncode == 0, (process.returncode, stdout, stderr)
    assert b"rate limit" not in stderr.lower(), stderr
    return stderr


def ssh_command(port: int, identity: pathlib.Path) -> list[str]:
    return [
        "ssh",
        "-F", "/dev/null",
        "-i", str(identity),
        "-o", "BatchMode=yes",
        "-o", "IdentitiesOnly=yes",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "LogLevel=ERROR",
        "-o", "ConnectTimeout=5",
        "-p", str(port),
        "tester@127.0.0.1",
    ]


def connect_raw(port: int, source: str = "127.0.0.1") -> socket.socket:
    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connection.settimeout(2)
    connection.bind((source, 0))
    connection.connect(("127.0.0.1", port))
    return connection


def receive_banner(connection: socket.socket) -> bytes:
    received = b""
    try:
        while b"\n" not in received:
            chunk = connection.recv(256)
            if not chunk:
                break
            received += chunk
    except (ConnectionResetError, socket.timeout):
        pass
    return received


def admitted_raw(port: int, source: str = "127.0.0.1") -> socket.socket:
    connection = connect_raw(port, source)
    banner = receive_banner(connection)
    assert banner.startswith(b"SSH-"), (source, banner)
    return connection


def assert_rejected_raw(port: int, source: str = "127.0.0.1") -> None:
    connection = connect_raw(port, source)
    try:
        banner = receive_banner(connection)
        assert not banner.startswith(b"SSH-"), (source, banner)
    finally:
        connection.close()


def start_shell(port: int, identity: pathlib.Path, marker: bytes) -> tuple[subprocess.Popen[bytes], bytes]:
    process = subprocess.Popen(
        ssh_command(port, identity) + ["-tt"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert process.stdin is not None
    assert process.stdout is not None
    process.stdin.write(marker + b"\n")
    process.stdin.flush()
    received = b""
    deadline = time.monotonic() + 10
    while marker not in received and time.monotonic() < deadline:
        if process.poll() is not None:
            _, stderr = process.communicate(timeout=1)
            raise AssertionError((process.returncode, received, stderr))
        readable, _, _ = select.select([process.stdout], [], [], 0.1)
        if readable:
            received += os.read(process.stdout.fileno(), 16 * 1024)
    assert marker in received, received
    return process, received


def finish_shell(process: subprocess.Popen[bytes], received: bytes, marker: bytes) -> None:
    assert process.stdin is not None
    process.stdin.write(marker + b"\n")
    process.stdin.flush()
    process.stdin.close()
    process.stdin = None
    stdout, stderr = process.communicate(timeout=15)
    assert process.returncode == 0, (process.returncode, received + stdout, stderr)
    assert marker in received + stdout, received + stdout


def test_concurrency(executable: pathlib.Path, directory: pathlib.Path,
                     client_key: pathlib.Path) -> None:
    port = reserve_port()
    server = start_server(
        executable, port, directory / "concurrency_host_key", client_key,
        [
            "--max-sessions", "2",
            "--max-sessions-per-ip", "1",
            "--connection-rate-limit", "100/1",
            "--auth-attempt-rate-limit", "100/1",
        ],
    )
    shell: subprocess.Popen[bytes] | None = None
    other: socket.socket | None = None
    try:
        shell, received = start_shell(port, client_key, b"concurrency-start")
        assert_rejected_raw(port)
        other = admitted_raw(port, "127.0.0.2")
        assert_rejected_raw(port, "127.0.0.3")
        finish_shell(shell, received, b"concurrency-survived")
        shell = None
    finally:
        if other is not None:
            other.close()
        if shell is not None:
            shell.kill()
            shell.communicate(timeout=5)
        stop_server(server)


def test_connection_rate(executable: pathlib.Path, directory: pathlib.Path,
                         client_key: pathlib.Path) -> None:
    port = reserve_port()
    server = start_server(
        executable, port, directory / "connection_host_key", client_key,
        [
            "--max-sessions", "4",
            "--max-sessions-per-ip", "4",
            "--connection-rate-limit", "2/60",
            "--auth-attempt-rate-limit", "100/1",
        ],
    )
    shell: subprocess.Popen[bytes] | None = None
    extra: socket.socket | None = None
    try:
        shell, received = start_shell(port, client_key, b"rate-start")
        extra = admitted_raw(port)
        extra.close()
        extra = None
        assert_rejected_raw(port)
        finish_shell(shell, received, b"rate-survived")
        shell = None
    finally:
        if extra is not None:
            extra.close()
        if shell is not None:
            shell.kill()
            shell.communicate(timeout=5)
        stop_server(server)


def test_auth_attempt_rate(executable: pathlib.Path, directory: pathlib.Path,
                           client_key: pathlib.Path, wrong_key: pathlib.Path) -> None:
    port = reserve_port()
    server = start_server(
        executable, port, directory / "auth_host_key", client_key,
        [
            "--max-sessions", "4",
            "--max-sessions-per-ip", "4",
            "--connection-rate-limit", "100/1",
            "--auth-attempt-rate-limit", "1/1",
            "--max-auth-attempts-per-session", "1",
        ],
    )
    shell: subprocess.Popen[bytes] | None = None
    recovered: socket.socket | None = None
    try:
        shell, received = start_shell(port, client_key, b"auth-start")
        denied = subprocess.run(ssh_command(port, wrong_key) + ["-T"], capture_output=True,
                                timeout=10, check=False)
        assert denied.returncode != 0, denied
        assert_rejected_raw(port)
        finish_shell(shell, received, b"auth-survived")
        shell = None

        time.sleep(1.1)
        recovered = admitted_raw(port)
    finally:
        if recovered is not None:
            recovered.close()
        if shell is not None:
            shell.kill()
            shell.communicate(timeout=5)
        stop_server(server)


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: test_ssh_admission.py ANVIL_EXECUTABLE")
    executable = pathlib.Path(sys.argv[1]).resolve()
    with tempfile.TemporaryDirectory(prefix="anvil-admission-test-") as directory_name:
        directory = pathlib.Path(directory_name)
        client_key = directory / "client_key"
        wrong_key = directory / "wrong_key"
        run_checked(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(client_key)])
        run_checked(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(wrong_key)])
        test_concurrency(executable, directory, client_key)
        test_connection_rate(executable, directory, client_key)
        test_auth_attempt_rate(executable, directory, client_key, wrong_key)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
